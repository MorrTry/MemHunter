#include <windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <windowsx.h>
#include <wrl/client.h>

#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

#include <algorithm>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "common/error.hpp"
#include "common/text.hpp"
#include "gui/lang.hpp"
#include "gui/session.hpp"
#include "gui/theme.hpp"
#include "gui/view.hpp"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

namespace {

using Microsoft::WRL::ComPtr;

constexpr wchar_t kWindowClass[] = L"MemHunterWindow";
constexpr float kDefaultWidth = 1400.0f;
constexpr float kDefaultHeight = 880.0f;
constexpr float kMinWidth = 960.0f;
constexpr float kMinHeight = 600.0f;
// Frames drawn after input before the loop sleeps again: ImGui spreads a click over several frames.
constexpr int kFramesAfterInput = 4;

// Not in every SDK; values from dwmapi.h of Windows 11.
constexpr DWORD kDwmUseDarkMode = 20;
constexpr DWORD kDwmBorderColor = 34;
constexpr DWORD kDwmCaptionColor = 35;
constexpr DWORD kDwmTextColor = 36;

[[noreturn]] void throw_hresult(const char* what, HRESULT result) {
    throw mh::Error(mh::ErrorCode::SystemError, std::string(what) + " (HRESULT " + mh::format_hex(static_cast<std::uint32_t>(result)) + ")");
}

// Common controls 6 for the message box and the save dialog. Without it they still work, in the classic look.
class VisualStyles {
public:
    explicit VisualStyles(HINSTANCE instance) {
        ACTCTXW context{};
        context.cbSize = sizeof(context);
        context.dwFlags = ACTCTX_FLAG_HMODULE_VALID | ACTCTX_FLAG_RESOURCE_NAME_VALID;
        context.hModule = instance;
        context.lpResourceName = MAKEINTRESOURCEW(2);
        handle_ = CreateActCtxW(&context);
        if (handle_ != INVALID_HANDLE_VALUE && !ActivateActCtx(handle_, &cookie_)) {
            ReleaseActCtx(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }
    ~VisualStyles() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            DeactivateActCtx(0, cookie_);
            ReleaseActCtx(handle_);
        }
    }
    VisualStyles(const VisualStyles&) = delete;
    VisualStyles& operator=(const VisualStyles&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    ULONG_PTR cookie_ = 0;
};

class ComScope {
public:
    ComScope() {
        const HRESULT result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if (FAILED(result)) {
            throw_hresult(mh::gui::tr("COM was not initialized", "COM не инициализирован"), result);
        }
    }
    ~ComScope() { CoUninitialize(); }
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;
};

class Graphics {
public:
    explicit Graphics(HWND hwnd) {
        DXGI_SWAP_CHAIN_DESC desc{};
        desc.BufferCount = 2;
        desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.BufferDesc.RefreshRate.Numerator = 60;
        desc.BufferDesc.RefreshRate.Denominator = 1;
        desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        desc.OutputWindow = hwnd;
        desc.SampleDesc.Count = 1;
        desc.Windowed = TRUE;
        desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        constexpr D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
        D3D_FEATURE_LEVEL level{};
        HRESULT result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &desc,
                                                       &swap_chain_, &device_, &level, &context_);
        if (FAILED(result)) {
            // No usable GPU driver (a virtual machine, a remote session): fall back to the software rasterizer.
            result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &desc,
                                                   &swap_chain_, &device_, &level, &context_);
        }
        if (FAILED(result)) {
            throw_hresult(mh::gui::tr("could not create the Direct3D 11 device", "не удалось создать устройство Direct3D 11"), result);
        }
        create_target();
    }

    ID3D11Device* device() const noexcept { return device_.Get(); }
    ID3D11DeviceContext* context() const noexcept { return context_.Get(); }

    void resize(UINT width, UINT height) {
        target_.Reset();
        const HRESULT result = swap_chain_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
        if (FAILED(result)) {
            throw_hresult(mh::gui::tr("could not resize the window buffers", "не удалось изменить размер буферов окна"), result);
        }
        create_target();
    }

    void begin(const float (&color)[4]) {
        context_->OMSetRenderTargets(1, target_.GetAddressOf(), nullptr);
        context_->ClearRenderTargetView(target_.Get(), color);
    }

    // False while the window is hidden or minimized.
    bool present() {
        const HRESULT result = swap_chain_->Present(1, 0);
        if (result == DXGI_STATUS_OCCLUDED) {
            return false;
        }
        if (FAILED(result)) {
            throw_hresult(mh::gui::tr("the video driver reset the output device", "видеодрайвер сбросил устройство вывода"), result);
        }
        return true;
    }

    bool visible() { return swap_chain_->Present(0, DXGI_PRESENT_TEST) != DXGI_STATUS_OCCLUDED; }

private:
    void create_target() {
        ComPtr<ID3D11Texture2D> back_buffer;
        HRESULT result = swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
        if (SUCCEEDED(result)) {
            result = device_->CreateRenderTargetView(back_buffer.Get(), nullptr, &target_);
        }
        if (FAILED(result)) {
            throw_hresult(mh::gui::tr("could not prepare the window buffer", "не удалось подготовить буфер окна"), result);
        }
    }

    ComPtr<ID3D11Device> device_;
    ComPtr<ID3D11DeviceContext> context_;
    ComPtr<IDXGISwapChain> swap_chain_;
    ComPtr<ID3D11RenderTargetView> target_;
};

class WindowPlatform final : public mh::gui::Platform {
public:
    explicit WindowPlatform(HWND hwnd) : hwnd_(hwnd) {}

    std::optional<std::filesystem::path> ask_save_path(const std::wstring& suggested_name, mh::gui::FileKind kind) override {
        std::wstring buffer(32768, L'\0');
        std::copy_n(suggested_name.begin(), std::min(suggested_name.size(), buffer.size() - 1), buffer.begin());
        OPENFILENAMEW dialog = file_dialog(buffer, kind);
        dialog.lpstrTitle = kind == mh::gui::FileKind::Pointers    ? mh::gui::tr(L"Save pointers", L"Сохранение указателей")
                            : kind == mh::gui::FileKind::Structure ? mh::gui::tr(L"Save structure", L"Сохранение структуры")
                                                                   : mh::gui::tr(L"Export results", L"Экспорт результатов");
        dialog.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (!GetSaveFileNameW(&dialog)) {
            return cancelled_or_failed(mh::gui::tr("the save dialog did not open", "окно сохранения не открылось"));
        }
        buffer.resize(std::wcslen(buffer.c_str()));
        return std::filesystem::path(buffer);
    }

    std::optional<std::filesystem::path> ask_open_path(mh::gui::FileKind kind) override {
        std::wstring buffer(32768, L'\0');
        OPENFILENAMEW dialog = file_dialog(buffer, kind);
        dialog.lpstrTitle = kind == mh::gui::FileKind::Structure ? mh::gui::tr(L"Load structure", L"Загрузка структуры")
                                                                 : mh::gui::tr(L"Load pointers", L"Загрузка указателей");
        dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (!GetOpenFileNameW(&dialog)) {
            return cancelled_or_failed(mh::gui::tr("the open-file dialog did not open", "окно открытия файла не открылось"));
        }
        buffer.resize(std::wcslen(buffer.c_str()));
        return std::filesystem::path(buffer);
    }

    void set_title(const std::string& title) override {
        // A failure only leaves the old title.
        SetWindowTextW(hwnd_, mh::utf8_to_wide(title).c_str());
    }

private:
    OPENFILENAMEW file_dialog(std::wstring& buffer, mh::gui::FileKind kind) const {
        static constexpr wchar_t exports_en[] = L"JSON (*.json)\0*.json\0CSV (*.csv)\0*.csv\0Text (*.txt)\0*.txt\0";
        static constexpr wchar_t exports_ru[] = L"JSON (*.json)\0*.json\0CSV (*.csv)\0*.csv\0Текст (*.txt)\0*.txt\0";
        static constexpr wchar_t pointers_en[] = L"MemHunter pointers (*.mhp)\0*.mhp\0";
        static constexpr wchar_t pointers_ru[] = L"Указатели MemHunter (*.mhp)\0*.mhp\0";
        static constexpr wchar_t structures_en[] = L"MemHunter structures (*.mhst)\0*.mhst\0All files (*.*)\0*.*\0";
        static constexpr wchar_t structures_ru[] = L"Структуры MemHunter (*.mhst)\0*.mhst\0Все файлы (*.*)\0*.*\0";
        const wchar_t* exports = mh::gui::tr(exports_en, exports_ru);
        const wchar_t* pointers = mh::gui::tr(pointers_en, pointers_ru);
        const wchar_t* structures = mh::gui::tr(structures_en, structures_ru);
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = hwnd_;
        dialog.nFilterIndex = 1;
        dialog.lpstrFile = buffer.data();
        dialog.nMaxFile = static_cast<DWORD>(buffer.size());
        switch (kind) {
            case mh::gui::FileKind::Pointers:
                dialog.lpstrFilter = pointers;
                dialog.lpstrDefExt = L"mhp";
                break;
            case mh::gui::FileKind::Structure:
                dialog.lpstrFilter = structures;
                dialog.lpstrDefExt = L"mhst";
                break;
            default:
                dialog.lpstrFilter = exports;
                dialog.lpstrDefExt = L"json";
                break;
        }
        return dialog;
    }

    static std::optional<std::filesystem::path> cancelled_or_failed(const char* what) {
        const DWORD error = CommDlgExtendedError();
        if (error == 0) {
            return std::nullopt;
        }
        throw mh::Error(mh::ErrorCode::SystemError, std::string(what) + mh::gui::tr(" (code ", " (код ") + mh::format_hex(error) + ")");
    }

    HWND hwnd_;
};

class ImGuiScope {
public:
    ImGuiScope() {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
    }
    ~ImGuiScope() { ImGui::DestroyContext(); }
    ImGuiScope(const ImGuiScope&) = delete;
    ImGuiScope& operator=(const ImGuiScope&) = delete;
};

class BackendScope {
public:
    BackendScope(HWND hwnd, const Graphics& graphics) {
        if (!ImGui_ImplWin32_Init(hwnd)) {
            throw mh::Error(mh::ErrorCode::SystemError, mh::gui::tr("could not attach ImGui to the window", "не удалось подключить ImGui к окну"));
        }
        if (!ImGui_ImplDX11_Init(graphics.device(), graphics.context())) {
            ImGui_ImplWin32_Shutdown();
            throw mh::Error(mh::ErrorCode::SystemError, mh::gui::tr("could not attach ImGui to Direct3D 11", "не удалось подключить ImGui к Direct3D 11"));
        }
    }
    ~BackendScope() {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
    }
    BackendScope(const BackendScope&) = delete;
    BackendScope& operator=(const BackendScope&) = delete;
};

// What the window procedure needs; reached through GWLP_USERDATA.
struct WindowState {
    UINT resize_width = 0;
    UINT resize_height = 0;
    std::optional<float> new_scale;
    float scale = 1.0f;
    bool input = false;
};

LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    auto* state = reinterpret_cast<WindowState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (state == nullptr) {
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
    state->input = true;
    if (ImGui::GetCurrentContext() != nullptr) {
        switch (message) {
            case WM_LBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_RBUTTONDOWN:
            case WM_RBUTTONUP:
            case WM_LBUTTONDBLCLK:
            case WM_RBUTTONDBLCLK:
                // A click carries its own position; posting it first keeps clicks right even without a move before them.
                ImGui::GetIO().AddMousePosEvent(static_cast<float>(GET_X_LPARAM(lparam)), static_cast<float>(GET_Y_LPARAM(lparam)));
                break;
            default: break;
        }
        if (ImGui_ImplWin32_WndProcHandler(hwnd, message, wparam, lparam)) {
            return 1;
        }
    }
    switch (message) {
        case WM_SIZE:
            if (wparam != SIZE_MINIMIZED) {
                state->resize_width = LOWORD(lparam);
                state->resize_height = HIWORD(lparam);
            }
            return 0;
        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
            info->ptMinTrackSize.x = static_cast<LONG>(kMinWidth * state->scale);
            info->ptMinTrackSize.y = static_cast<LONG>(kMinHeight * state->scale);
            return 0;
        }
        case WM_DPICHANGED: {
            state->new_scale = static_cast<float>(HIWORD(wparam)) / 96.0f;
            state->scale = *state->new_scale;
            const auto* rect = reinterpret_cast<const RECT*>(lparam);
            SetWindowPos(hwnd, nullptr, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        case WM_SYSCOMMAND:
            // The Alt key would open the window menu and beep.
            if ((wparam & 0xFFF0) == SC_KEYMENU) {
                return 0;
            }
            break;
        case WM_DESTROY: PostQuitMessage(0); return 0;
        default: break;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

void style_caption(HWND hwnd) {
    // Black caption with white text to match the window; older Windows versions ignore these and keep their own.
    const BOOL dark = TRUE;
    const COLORREF black = RGB(0, 0, 0);
    const COLORREF white = RGB(255, 255, 255);
    DwmSetWindowAttribute(hwnd, kDwmUseDarkMode, &dark, sizeof(dark));
    DwmSetWindowAttribute(hwnd, kDwmCaptionColor, &black, sizeof(black));
    DwmSetWindowAttribute(hwnd, kDwmTextColor, &white, sizeof(white));
    DwmSetWindowAttribute(hwnd, kDwmBorderColor, &white, sizeof(white));
}

HWND create_window(HINSTANCE instance, WindowState& state) {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_CLASSDC | CS_DBLCLKS;
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    window_class.lpszClassName = kWindowClass;
    window_class.hIcon = static_cast<HICON>(
        LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR));
    window_class.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                                                         GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR));
    if (RegisterClassExW(&window_class) == 0) {
        mh::throw_win32(mh::ErrorCode::SystemError, mh::gui::tr("could not register the window class", "не удалось зарегистрировать класс окна"), GetLastError());
    }

    POINT cursor{};
    GetCursorPos(&cursor);
    HMONITOR monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTOPRIMARY);
    state.scale = ImGui_ImplWin32_GetDpiScaleForMonitor(monitor);
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    RECT work{0, 0, 1920, 1040};
    if (GetMonitorInfoW(monitor, &info)) {
        work = info.rcWork;
    }
    const int work_width = work.right - work.left;
    const int work_height = work.bottom - work.top;
    const int width = std::min(static_cast<int>(kDefaultWidth * state.scale), work_width * 92 / 100);
    const int height = std::min(static_cast<int>(kDefaultHeight * state.scale), work_height * 92 / 100);
    HWND hwnd = CreateWindowExW(0, kWindowClass, L"MemHunter", WS_OVERLAPPEDWINDOW, work.left + (work_width - width) / 2,
                                work.top + (work_height - height) / 2, width, height, nullptr, nullptr, instance, &state);
    if (hwnd == nullptr) {
        mh::throw_win32(mh::ErrorCode::SystemError, mh::gui::tr("could not create the window", "не удалось создать окно"), GetLastError());
    }
    state.scale = ImGui_ImplWin32_GetDpiScaleForHwnd(hwnd);
    style_caption(hwnd);
    return hwnd;
}

std::vector<std::wstring> command_line_arguments() {
    int count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (arguments == nullptr) {
        mh::throw_win32(mh::ErrorCode::SystemError, mh::gui::tr("could not parse the command line", "не удалось разобрать командную строку"), GetLastError());
    }
    std::vector<std::wstring> result(arguments, arguments + count);
    LocalFree(arguments);
    return result;
}

void configure_imgui() {
    ImGuiIO& io = ImGui::GetIO();
    // Nothing is stored between runs: no imgui.ini next to the executable.
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigInputTextCursorBlink = false;
    io.ConfigWindowsMoveFromTitleBarOnly = true;
}

class Fonts {
public:
    void load(float scale) {
        fonts_ = loader_.load(ImGui::GetIO(), scale);
        mh::gui::theme::apply_style(ImGui::GetStyle(), scale);
    }
    const mh::gui::theme::Fonts& get() const noexcept { return fonts_; }

private:
    mh::gui::theme::FontLoader loader_;
    mh::gui::theme::Fonts fonts_;
};

int run(HINSTANCE instance, int show) {
    ComScope com;
    WindowState state;
    HWND hwnd = create_window(instance, state);
    Graphics graphics(hwnd);

    ImGuiScope imgui;
    configure_imgui();
    Fonts fonts;
    fonts.load(state.scale);
    BackendScope backend(hwnd, graphics);

    mh::gui::Session session;
    WindowPlatform platform(hwnd);
    mh::gui::View view(session, platform, fonts.get());
    view.set_scale(state.scale);

    std::vector<std::wstring> arguments = command_line_arguments();
    const auto flag = std::remove(arguments.begin() + std::min<std::ptrdiff_t>(1, std::ssize(arguments)), arguments.end(),
                                  std::wstring(L"--debug-privilege"));
    const bool debug_privilege = flag != arguments.end();
    arguments.erase(flag, arguments.end());
    // Without the privilege the process may not open, and the picker shows why.
    const bool privileged = !debug_privilege || view.set_debug_privilege(true);
    if (arguments.size() >= 2 && privileged) {
        view.open_from_command_line(mh::wide_to_utf8(arguments[1]));
    } else {
        view.show_picker();
    }

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    int frames_left = kFramesAfterInput;
    bool occluded = false;
    for (;;) {
        if (frames_left == 0 || occluded) {
            const DWORD timeout = occluded ? 200u : view.frame_interval_ms();
            MsgWaitForMultipleObjectsEx(0, nullptr, timeout, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        }
        state.input = false;
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            if (message.message == WM_QUIT) {
                return static_cast<int>(message.wParam);
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        frames_left = state.input ? kFramesAfterInput : std::max(frames_left - 1, 0);

        if (occluded) {
            if (!graphics.visible()) {
                continue;
            }
            occluded = false;
        }
        if (state.new_scale) {
            fonts.load(*state.new_scale);
            view.set_scale(*state.new_scale);
            ImGui_ImplDX11_InvalidateDeviceObjects();
            state.new_scale.reset();
        }
        if (state.resize_width != 0 && state.resize_height != 0) {
            graphics.resize(state.resize_width, state.resize_height);
            state.resize_width = state.resize_height = 0;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        view.draw();
        ImGui::Render();
        constexpr float black[4] = {0.0f, 0.0f, 0.0f, 1.0f};
        graphics.begin(black);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        occluded = !graphics.present();
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    // Sharp text on every monitor; the fallback covers Windows 10 before 1703.
    if (!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
        ImGui_ImplWin32_EnableDpiAwareness();
    }
    const VisualStyles styles(instance);
    try {
        return run(instance, show);
    } catch (const std::exception& error) {
        const std::wstring text =
            mh::gui::tr(L"MemHunter cannot continue:\n\n", L"MemHunter не может продолжить работу:\n\n") + mh::utf8_to_wide(error.what());
        MessageBoxW(nullptr, text.c_str(), L"MemHunter", MB_OK | MB_ICONERROR);
        return 1;
    }
}
