#include "gui/session.hpp"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <ostream>

#include "common/text.hpp"
#include "memory/process_memory.hpp"
#include "pointer/pointer_file.hpp"
#include "process/process.hpp"
#include "results/export.hpp"

namespace mh::gui {

namespace {

class ProcessTarget final : public Target {
public:
    explicit ProcessTarget(Process process) : process_(std::move(process)), memory_(process_) {
        summary_.pid = process_.pid();
        summary_.name = process_.image_name();
        summary_.path = process_.image_path();
        summary_.creation_time = process_.creation_time();
        summary_.wow64 = process_.is_wow64();
    }
    ProcessTarget(const ProcessTarget&) = delete;
    ProcessTarget& operator=(const ProcessTarget&) = delete;

    const MemorySource& memory() const override { return memory_; }
    const ProcessSummary& summary() const override { return summary_; }

private:
    Process process_;
    ProcessMemory memory_;
    ProcessSummary summary_;
};

OutputFormat format_of(const std::filesystem::path& path) {
    const std::string extension = to_lower_ascii(wide_to_utf8(path.extension().wstring()));
    return extension == ".csv" ? OutputFormat::Csv : extension == ".txt" ? OutputFormat::Text : OutputFormat::Json;
}

}  // namespace

std::unique_ptr<Target> open_process(std::uint32_t pid) {
    return std::make_unique<ProcessTarget>(Process::open(pid));
}

std::string describe_error(const Error& error) {
    switch (error.code()) {
        case ErrorCode::AccessDenied:
            return "Нет доступа к процессу. Windows не разрешила открыть его для чтения. Так бывает с процессами другого "
                   "пользователя и процессами, запущенными от имени администратора (тогда и MemHunter нужно запускать так же), "
                   "с системными и защищёнными процессами, а также когда процесс сам запрещает доступ к себе.";
        case ErrorCode::ProcessNotFound: return "Процесс не найден: возможно, он уже завершился.";
        case ErrorCode::ProcessExited: return "Процесс уже завершился.";
        case ErrorCode::Io: return std::string("Ошибка файла: ") + error.what();
        case ErrorCode::SystemError: return std::string("Ошибка Windows: ") + error.what();
        default: return error.what();
    }
}

bool MemoryDump::all_readable(std::uint64_t begin, std::uint64_t end) const {
    if (begin < address || end > address + bytes.size() || begin > end) {
        return false;
    }
    return std::all_of(readable.begin() + static_cast<std::ptrdiff_t>(begin - address),
                       readable.begin() + static_cast<std::ptrdiff_t>(end - address), [](std::uint8_t r) { return r != 0; });
}

MemoryDump read_dump(const MemorySource& memory, std::uint64_t address, std::size_t size) {
    MemoryDump dump;
    dump.address = address;
    size = static_cast<std::size_t>(std::min<std::uint64_t>(size, ~std::uint64_t{0} - address));
    dump.bytes.assign(size, std::byte{0});
    dump.readable.assign(size, 0);
    const std::uint64_t page = std::max<std::size_t>(memory.page_size(), 1);
    std::size_t offset = 0;
    while (offset < size) {
        const std::uint64_t at = address + offset;
        const std::size_t piece = static_cast<std::size_t>(std::min<std::uint64_t>(size - offset, page - at % page));
        const ReadResult read = memory.read(at, std::span(dump.bytes).subspan(offset, piece));
        std::fill_n(dump.readable.begin() + static_cast<std::ptrdiff_t>(offset), std::min(read.bytes, piece), std::uint8_t{1});
        offset += piece;
    }
    return dump;
}

LiveState live_state(const ResultSet& results, std::span<const Pattern> patterns, const Match& match, const MemoryDump& dump) {
    const std::uint64_t end = match.address + match.length;
    if (match.length == 0 || !dump.all_readable(match.address, end)) {
        return LiveState::Unreadable;
    }
    const std::byte* data = dump.bytes.data() + (match.address - dump.address);
    if (match.pattern < patterns.size() && patterns[match.pattern].size() == match.length) {
        return patterns[match.pattern].matches(reinterpret_cast<const std::uint8_t*>(data)) ? LiveState::Same : LiveState::Changed;
    }
    const auto found = results.preview(match);
    const std::size_t compared = std::min<std::size_t>(found.size(), match.length);
    return std::equal(found.begin(), found.begin() + static_cast<std::ptrdiff_t>(compared), data) ? LiveState::Same : LiveState::Changed;
}

namespace {

template <typename Write>
void write_file(const std::filesystem::path& path, Write&& write) {
    const std::string name = wide_to_utf8(path.wstring());
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw Error(ErrorCode::Io, "не удалось создать «" + name + "»");
    }
    write(out, format_of(path));
    out.close();
    if (!out) {
        throw Error(ErrorCode::Io, "не удалось записать «" + name + "» (диск заполнен?)");
    }
}

}  // namespace

void export_rows(const std::filesystem::path& path, const ResultSet& results, std::span<const std::size_t> rows) {
    write_file(path, [&](std::ostream& out, OutputFormat format) { write_results(out, format, results, rows, ExportOptions{}); });
}

namespace {

void write_values(std::ostream& out, OutputFormat format, const ProcessSummary& process, const ValueTable& table) {
    const ValueCandidates& candidates = *table.candidates();
    const std::string type(to_string(candidates.type));
    const auto& rows = table.rows();
    switch (format) {
        case OutputFormat::Csv:
            out << "address,value,type,protection,memory,module\n";
            for (std::size_t row = 0; row < rows.size(); ++row) {
                const Region* region = table.region(row);
                out << format_address(rows[row].address) << ',' << csv_field(table.previous_text(row)) << ',' << type << ','
                    << (region != nullptr ? protection_to_string(region->protect) : std::string()) << ','
                    << (region != nullptr ? std::string(to_string(region->type)) : std::string()) << ','
                    << csv_field(table.module(row)) << '\n';
            }
            break;
        case OutputFormat::Text:
            out << "process " << process.name << " (pid " << process.pid << "), " << type << ", scan " << candidates.scans << ", "
                << table.total() << " addresses, " << rows.size() << " shown\n";
            for (std::size_t row = 0; row < rows.size(); ++row) {
                out << format_address(rows[row].address) << "  " << table.previous_text(row) << "  " << table.module(row) << '\n';
            }
            break;
        case OutputFormat::Json:
            out << "{\n  \"process\": {\"pid\": " << process.pid << ", \"name\": \"" << json_escape(process.name) << "\"},\n"
                << "  \"value_type\": \"" << type << "\",\n  \"scan\": " << candidates.scans << ",\n  \"total\": " << table.total()
                << ",\n  \"values\": [";
            for (std::size_t row = 0; row < rows.size(); ++row) {
                const Region* region = table.region(row);
                out << (row == 0 ? "\n" : ",\n") << "    {\"address\": \"" << format_address(rows[row].address) << "\", \"value\": \""
                    << json_escape(table.previous_text(row)) << "\", \"protection\": \""
                    << (region != nullptr ? protection_to_string(region->protect) : std::string()) << "\", \"memory\": \""
                    << (region != nullptr ? std::string(to_string(region->type)) : std::string()) << "\", \"module\": \""
                    << json_escape(table.module(row)) << "\"}";
            }
            out << (rows.empty() ? "]\n}\n" : "\n  ]\n}\n");
            break;
    }
}

void write_watch(std::ostream& out, OutputFormat format, const ProcessSummary& process, const WatchList& list, const MemorySource& memory) {
    const auto& rows = list.rows();
    struct Now {
        std::optional<std::uint64_t> address;
        std::optional<std::string> value;
        std::string pointer;
    };
    const auto now = [&](std::size_t row) {
        Now result;
        WatchEntry entry = rows[row];
        result.address = list.locate(memory, row);
        if (result.address) {
            entry.address = *result.address;
            if (const auto bytes = read_watch_value(memory, entry)) {
                result.value = format_watch_value(entry, *bytes);
            }
        }
        if (entry.path) {
            result.pointer = format_pointer_path(*entry.path);
        }
        return result;
    };
    switch (format) {
        case OutputFormat::Csv:
            out << "address,type,length,value,description,module,pointer\n";
            for (std::size_t row = 0; row < rows.size(); ++row) {
                const WatchEntry& entry = rows[row];
                const Now current = now(row);
                out << (current.address ? format_address(*current.address) : std::string()) << ',' << to_string(entry.type) << ','
                    << (has_length(entry.type) ? std::to_string(entry.length) : std::string()) << ','
                    << csv_field(current.value.value_or("")) << ',' << csv_field(entry.description) << ',' << csv_field(list.module(row))
                    << ',' << csv_field(current.pointer) << '\n';
            }
            break;
        case OutputFormat::Text:
            out << "process " << process.name << " (pid " << process.pid << "), " << rows.size() << " addresses\n";
            for (std::size_t row = 0; row < rows.size(); ++row) {
                const WatchEntry& entry = rows[row];
                const Now current = now(row);
                out << (current.address ? format_address(*current.address) : std::string("??")) << "  " << type_label(entry) << "  "
                    << current.value.value_or("??");
                for (const std::string& extra : {list.module(row), entry.description, current.pointer}) {
                    if (!extra.empty()) {
                        out << "  " << extra;
                    }
                }
                out << '\n';
            }
            break;
        case OutputFormat::Json:
            out << "{\n  \"process\": {\"pid\": " << process.pid << ", \"name\": \"" << json_escape(process.name) << "\"},\n"
                << "  \"addresses\": [";
            for (std::size_t row = 0; row < rows.size(); ++row) {
                const WatchEntry& entry = rows[row];
                const Now current = now(row);
                out << (row == 0 ? "\n" : ",\n") << "    {\"address\": "
                    << (current.address ? '"' + format_address(*current.address) + '"' : std::string("null")) << ", \"type\": \""
                    << to_string(entry.type) << '"';
                if (has_length(entry.type)) {
                    out << ", \"length\": " << entry.length;
                }
                out << ", \"value\": " << (current.value ? '"' + json_escape(*current.value) + '"' : std::string("null"))
                    << ", \"description\": \"" << json_escape(entry.description) << "\", \"module\": \""
                    << json_escape(list.module(row)) << '"';
                if (entry.path) {
                    out << ", \"pointer\": \"" << json_escape(current.pointer) << '"';
                }
                out << '}';
            }
            out << (rows.empty() ? "]\n}\n" : "\n  ]\n}\n");
            break;
    }
}

}  // namespace

void export_values(const std::filesystem::path& path, const ProcessSummary& process, const ValueTable& table) {
    if (!table.has_values()) {
        throw Error(ErrorCode::InvalidArgument, "нет найденных значений");
    }
    write_file(path, [&](std::ostream& out, OutputFormat format) { write_values(out, format, process, table); });
}

void export_watch(const std::filesystem::path& path, const ProcessSummary& process, const WatchList& list, const MemorySource& memory) {
    if (list.empty()) {
        throw Error(ErrorCode::InvalidArgument, "список адресов пуст");
    }
    write_file(path, [&](std::ostream& out, OutputFormat format) { write_watch(out, format, process, list, memory); });
}

Session::~Session() {
    stop_job();
}

void Session::stop_job() {
    if (job_) {
        job_->cancel();
        job_.reset();
    }
}

void Session::attach(std::unique_ptr<Target> target) {
    stop_job();
    if (!target_ || !target) {
        watch_ = WatchList{};
    } else {
        const ProcessSummary& before = target_->summary();
        const ProcessSummary& after = target->summary();
        if (before.pid != after.pid || before.creation_time != after.creation_time) {
            if (iequals_ascii(before.name, after.name)) {
                watch_.keep_paths();
            } else {
                watch_ = WatchList{};
            }
        }
    }
    table_.clear();
    patterns_.clear();
    baseline_.reset();
    changes_.reset();
    values_.clear();
    value_run_ = {};
    history_.clear();
    target_ = std::move(target);
    if (target_) {
        refresh_modules();
        const ProcessSummary& process = target_->summary();
        set_notice("Открыт процесс " + process.name + " (PID " + std::to_string(process.pid) + ")", false);
    }
}

void Session::detach() {
    attach(nullptr);
    notice_ = {};
}

bool Session::add_watch(WatchEntry entry) {
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    refresh_modules();
    const std::string address = format_address(entry.address);
    const bool added = watch_.add(std::move(entry));
    set_notice(address + (added ? " добавлен в список адресов" : " уже в списке адресов"), false);
    return added;
}

bool Session::target_alive() const {
    return target_ && target_->memory().target_alive();
}

void Session::set_notice(std::string text, bool error) {
    notice_ = {std::move(text), error};
}

bool Session::start_scan(const SearchForm& form, bool only_changed) {
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    if (job_) {
        return false;
    }
    if (only_changed && !baseline_) {
        set_notice("Сначала нажмите «Запомнить память», затем измените данные в программе", true);
        return false;
    }
    ScanRequest request;
    try {
        request = build_request(form);
    } catch (const Error& error) {
        set_notice(describe_error(error), true);
        return false;
    }
    pending_patterns_ = request.patterns;
    table_.clear();
    patterns_.clear();
    changes_.reset();
    notice_ = {};
    const MemorySource& memory = target_->memory();
    if (only_changed) {
        job_ = std::make_unique<Job>(JobKind::ChangedScan,
                                     changed_scan_work(memory, target_->summary(), std::move(request), baseline_->snapshot));
    } else {
        job_ = std::make_unique<Job>(JobKind::Scan, scan_work(memory, target_->summary(), std::move(request)));
    }
    return true;
}

bool Session::start_remember(const SearchForm& form) {
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    if (job_) {
        return false;
    }
    RegionFilter filter;
    unsigned threads = 0;
    try {
        filter = region_filter(form);
        threads = thread_count(form);
    } catch (const Error& error) {
        set_notice(describe_error(error), true);
        return false;
    }
    notice_ = {};
    job_ = std::make_unique<Job>(JobKind::Remember, remember_work(target_->memory(), target_->summary(), std::move(filter), threads));
    return true;
}

void Session::forget() {
    if (job_ && (job_->kind() == JobKind::ChangedScan || job_->kind() == JobKind::Remember)) {
        return;
    }
    baseline_.reset();
    set_notice("Запомненная память сброшена", false);
}

bool Session::start_value_scan(const SearchForm& form) {
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    if (job_) {
        return false;
    }
    std::shared_ptr<const ValueCandidates> previous = values_.candidates();
    const NumberType type = previous ? previous->type : form.number_type;
    RegionFilter filter;
    ValueCondition condition;
    ValueScanOptions options;
    try {
        if (previous && form.compare == Compare::Unknown) {
            throw Error(ErrorCode::InvalidArgument, "«Неизвестное значение» — только для первого поиска");
        }
        if (!previous && needs_previous(form.compare)) {
            throw Error(ErrorCode::InvalidArgument, "Сравнивать с прошлым значением можно после первого поиска");
        }
        condition = value_condition(form, type);
        options.threads = thread_count(form);
        if (!previous) {
            filter = region_filter(form);
            options.memory_budget = value_memory_budget();
            history_budget_ = options.memory_budget;
        }
    } catch (const Error& error) {
        set_notice(describe_error(error), true);
        return false;
    }
    notice_ = {};
    pending_label_ = describe_scan(form, type, !previous);
    const bool aligned = previous ? previous->aligned : form.aligned;
    job_ = std::make_unique<Job>(JobKind::ValueScan, value_scan_work(target_->memory(), std::move(filter), type, aligned, condition,
                                                                     options, std::move(previous)));
    return true;
}

void Session::reset_values() {
    if (job_ && job_->kind() == JobKind::ValueScan) {
        return;
    }
    values_.clear();
    value_run_ = {};
    history_.clear();
    notice_ = {};
}

bool Session::go_to_scan(std::size_t step) {
    if (job_ || step >= history_.steps().size()) {
        return false;
    }
    history_.go_to(step);
    const HistoryStep& shown = history_.steps()[step];
    values_.assign(shown.candidates);
    set_notice("Показан поиск " + std::to_string(shown.candidates->scans) + ": " + count_addresses(shown.count), false);
    return true;
}

void Session::cancel() {
    if (job_) {
        job_->cancel();
    }
}

bool Session::poll() {
    if (!job_ || !job_->finished()) {
        return false;
    }
    const JobKind kind = job_->kind();
    const double seconds = job_->elapsed_seconds();
    try {
        JobOutcome outcome = job_->take();
        job_.reset();
        finish(kind, std::move(outcome), seconds);
    } catch (const Error& error) {
        job_.reset();
        set_notice(describe_error(error), true);
    } catch (const std::exception& error) {
        job_.reset();
        set_notice(std::string("Сбой: ") + error.what(), true);
    }
    return true;
}

void Session::finish_values(ValueScanResult result, double seconds) {
    const bool next = values_.has_values();
    value_run_ = {result.bytes_read, result.read_failures, result.threads};
    switch (result.status) {
        case ValueScanStatus::Completed: {
            const std::uint64_t before = values_.total();
            const std::uint64_t count = result.candidates.count();
            const unsigned scan = result.candidates.scans;
            if (!next && count == 0) {
                set_notice("Ничего не найдено за " + format_seconds(seconds) + ". Проверьте тип и значение", false);
                return;
            }
            values_.assign(std::make_shared<const ValueCandidates>(std::move(result.candidates)));
            history_.push(values_.candidates(), std::move(pending_label_), history_budget_);
            std::string text = "Поиск " + std::to_string(scan) + ": ";
            if (next) {
                text += "осталось " + count_addresses(count) + " из " + group_digits(before) + " за " + format_seconds(seconds);
                if (count == 0) {
                    text += ". Вернитесь к прошлому поиску (Ctrl+Z) или начните заново: «Новый поиск»";
                }
            } else {
                text += "найдено " + count_addresses(count) + " за " + format_seconds(seconds) +
                        ". Измените значение в программе и выберите, как оно изменилось";
            }
            set_notice(std::move(text), false);
            return;
        }
        case ValueScanStatus::Cancelled: set_notice(next ? "Поиск остановлен, результаты прежние" : "Поиск остановлен", false); return;
        case ValueScanStatus::TargetExited: set_notice("Процесс завершился во время поиска", true); return;
        case ValueScanStatus::OverBudget:
            set_notice("Слишком много адресов: списку нужно больше " + format_size(result.needed_bytes) +
                           ", это больше трети свободной памяти. Введите известное значение, выберите тип покрупнее "
                           "или отметьте меньше видов памяти",
                       true);
            return;
    }
}

void Session::finish(JobKind kind, JobOutcome outcome, double seconds) {
    if (kind == JobKind::PointerScan) {
        if (outcome.pointers) {
            const PointerScanResult& result = *outcome.pointers;
            pointer_run_ = {kind, seconds, result.threads, result.bytes_read, result.read_failures, result.pointers};
            finish_pointers(std::move(*outcome.pointers), seconds);
        }
        return;
    }
    if (kind == JobKind::PointerCheck) {
        if (outcome.checked) {
            pointer_run_ = {kind, seconds, outcome.checked->threads, 0, 0, 0};
            finish_check(std::move(*outcome.checked), seconds);
        }
        return;
    }
    last_seconds_ = seconds;
    if (kind == JobKind::ValueScan) {
        if (outcome.values) {
            finish_values(std::move(*outcome.values), seconds);
        }
        return;
    }
    if (kind == JobKind::Remember) {
        if (outcome.snapshot) {
            const std::uint64_t bytes = outcome.snapshot->captured_bytes();
            baseline_ = Baseline{std::make_shared<const Snapshot>(std::move(*outcome.snapshot)), bytes};
            set_notice("Память запомнена (" + format_size(bytes) +
                           "). Измените данные в программе и ищите с отметкой «Только изменившаяся память».",
                       false);
        } else if (outcome.status == ScanStatus::TargetExited) {
            set_notice("Процесс завершился, память не запомнена", true);
        } else {
            set_notice("Запоминание остановлено", false);
        }
        return;
    }

    changes_ = outcome.changes;
    if (!outcome.results) {
        set_notice(outcome.status == ScanStatus::TargetExited ? "Процесс завершился до начала поиска" : "Поиск остановлен", false);
        return;
    }
    const bool truncated = outcome.results->stats.truncated;
    patterns_ = std::move(pending_patterns_);
    table_.assign(std::move(*outcome.results));
    const std::string count = count_matches(table_.results().matches.size());
    std::string text;
    switch (outcome.status) {
        case ScanStatus::Completed: text = "Найдено " + count + " за " + format_seconds(seconds); break;
        case ScanStatus::Cancelled: text = "Поиск остановлен: " + count + " в просмотренной части"; break;
        case ScanStatus::TargetExited: text = "Процесс завершился во время поиска: " + count + " до этого"; break;
    }
    if (changes_) {
        text += ". Изменилось " + format_size(changes_->changed) + " из " + format_size(changes_->compared);
    }
    if (truncated) {
        text += ". Достигнут лимит совпадений";
    }
    set_notice(std::move(text), false);
}

void Session::refresh_modules() {
    if (!target_) {
        return;
    }
    try {
        std::vector<Region> regions = target_->memory().query_regions();
        pointers_.set_modules(ModuleMap(regions));
        watch_.set_regions(std::move(regions));
    } catch (const Error&) {
        // The process is exiting; the lists keep the modules read before.
    }
}

bool Session::start_pointer_scan(std::size_t watch_row, unsigned depth, std::uint32_t max_offset, unsigned threads) {
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    if (job_) {
        return false;
    }
    if (watch_row >= watch_.rows().size()) {
        set_notice("Выберите в списке адресов адрес, к которому искать указатели", true);
        return false;
    }
    if (depth == 0 || depth > kMaxPointerDepth) {
        set_notice("Глубина — от 1 до " + std::to_string(kMaxPointerDepth), true);
        return false;
    }
    const WatchEntry& entry = watch_.rows()[watch_row];
    if (entry.path && (!watch_.read(watch_row) || !watch_.resolved(watch_row))) {
        set_notice("Цепочка этой записи сейчас никуда не ведёт", true);
        return false;
    }
    PointerScanOptions options;
    options.depth = depth;
    options.max_offset = max_offset;
    options.threads = threads;
    options.memory_budget = pointer_memory_budget();
    pending_search_ = PointerSearch{};
    pending_search_.process = target_->summary();
    pending_search_.target = make_watch_entry(entry.address, entry.type, entry.length, entry.description);
    pending_search_.depth = depth;
    pending_search_.max_offset = max_offset;
    notice_ = {};
    const unsigned pointer_size = target_->summary().wow64 ? 4 : 8;
    job_ = std::make_unique<Job>(JobKind::PointerScan, pointer_scan_work(target_->memory(), entry.address, pointer_size, options));
    return true;
}

void Session::finish_pointers(PointerScanResult result, double seconds) {
    switch (result.status) {
        case PointerScanStatus::Completed: {
            const std::size_t listed = result.chains.chains.size();
            if (listed == 0) {
                set_notice("Цепочек не найдено за " + format_seconds(seconds) + ". Увеличьте глубину или наибольшее смещение", false);
                return;
            }
            std::string text = "Найдено цепочек: " + group_digits(result.total_chains) + " за " + format_seconds(seconds);
            if (result.truncated()) {
                text += ". В списке самые короткие " + group_digits(listed);
            }
            pending_search_.found = result.total_chains;
            pointers_.assign(std::make_shared<const PointerChains>(std::move(result.chains)), std::move(pending_search_));
            refresh_modules();
            set_notice(std::move(text), false);
            return;
        }
        case PointerScanStatus::Cancelled: set_notice("Поиск указателей остановлен", false); return;
        case PointerScanStatus::TargetExited: set_notice("Процесс завершился во время поиска указателей", true); return;
        case PointerScanStatus::OverBudget:
            set_notice("Слишком много указателей: поиску нужно больше " + format_size(result.needed_bytes) +
                           ", это больше трети свободной памяти. Уменьшите глубину или наибольшее смещение",
                       true);
            return;
    }
}

bool Session::start_pointer_check(const PointerCheckForm& form, unsigned threads) {
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    if (job_) {
        return false;
    }
    if (!pointers_.has_chains()) {
        set_notice("Сначала найдите указатели или загрузите их из файла", true);
        return false;
    }
    PointerCheck check;
    try {
        if (form.by_value) {
            const auto type = value_type(pointers_.search().target.type);
            if (!type) {
                throw Error(ErrorCode::InvalidArgument, "По значению проверяются только числа. Найдите адрес заново и проверьте по нему");
            }
            SearchForm number;
            number.number = form.value;
            number.compare = Compare::Exact;
            check.type = *type;
            check.condition = value_condition(number, *type);
        } else {
            check.address = parse_address(form.address);
            if (!check.address) {
                throw Error(ErrorCode::InvalidArgument,
                            form.address.empty() ? "Введите адрес" : "Адрес — шестнадцатеричное число, например 0x7FF6A0001000");
            }
        }
    } catch (const Error& error) {
        set_notice(describe_error(error), true);
        return false;
    }
    pending_address_ = check.address;
    notice_ = {};
    job_ = std::make_unique<Job>(JobKind::PointerCheck, pointer_check_work(target_->memory(), pointers_.chains(), check, threads));
    return true;
}

void Session::finish_check(PointerFilterResult result, double seconds) {
    switch (result.status) {
        case PointerScanStatus::Completed: {
            const std::size_t before = pointers_.rows().size();
            const std::size_t kept = result.chains.chains.size();
            if (kept == 0) {
                const std::string goal =
                    pending_address_ ? "к адресу " + format_address(*pending_address_) : std::string("к такому значению");
                set_notice("Ни одна цепочка не ведёт " + goal + ". Список прежний: проверьте, что ввели", true);
                return;
            }
            PointerSearch search = pointers_.search();
            search.process = target_->summary();
            ++search.checks;
            if (pending_address_) {
                search.target.address = *pending_address_;
            }
            pointers_.assign(std::make_shared<const PointerChains>(std::move(result.chains)), std::move(search));
            refresh_modules();
            set_notice("Осталось цепочек: " + group_digits(kept) + " из " + group_digits(before) + " за " + format_seconds(seconds),
                       false);
            return;
        }
        case PointerScanStatus::TargetExited: set_notice("Процесс завершился во время проверки", true); return;
        default: set_notice("Проверка остановлена, список прежний", false); return;
    }
}

bool Session::save_pointers(const std::filesystem::path& path) {
    if (!pointers_.has_chains()) {
        set_notice("Список указателей пуст", true);
        return false;
    }
    const PointerSearch& search = pointers_.search();
    PointerFile file;
    file.process = search.process;
    file.target = search.target.address;
    file.target_type = static_cast<std::uint8_t>(search.target.type);
    file.target_length = search.target.length;
    file.depth = search.depth;
    file.max_offset = search.max_offset;
    file.checks = search.checks;
    file.chains = *pointers_.chains();
    try {
        const std::uint64_t size = write_pointer_file(wide_to_utf8(path.wstring()), file);
        set_notice("Сохранено цепочек: " + group_digits(file.chains.chains.size()) + " в " +
                       wide_to_utf8(path.filename().wstring()) + " (" + format_size(size) + ")",
                   false);
        return true;
    } catch (const Error& error) {
        set_notice(describe_error(error), true);
        return false;
    }
}

bool Session::load_pointers(const std::filesystem::path& path) {
    if (job_) {
        return false;
    }
    PointerFile file;
    try {
        file = read_pointer_file(wide_to_utf8(path.wstring()));
    } catch (const Error& error) {
        if (error.code() == ErrorCode::CorruptSnapshot) {
            set_notice(std::string("Это не файл указателей MemHunter, или он повреждён (") + error.what() + ")", true);
        } else if (error.code() == ErrorCode::IncompatibleSnapshot) {
            set_notice("Файл сохранён более новой версией MemHunter", true);
        } else {
            set_notice(describe_error(error), true);
        }
        return false;
    }
    PointerSearch search;
    search.process = file.process;
    search.target = make_watch_entry(file.target, static_cast<WatchType>(file.target_type), file.target_length);
    search.depth = file.depth;
    search.max_offset = file.max_offset;
    search.checks = file.checks;
    search.found = file.chains.chains.size();
    const std::size_t count = file.chains.chains.size();
    pointers_.assign(std::make_shared<const PointerChains>(std::move(file.chains)), std::move(search));
    refresh_modules();
    set_notice("Загружено цепочек: " + group_digits(count) + " из " + wide_to_utf8(path.filename().wstring()), false);
    return true;
}

void Session::clear_pointers() {
    if (job_ && job_->kind() == JobKind::PointerCheck) {
        return;
    }
    pointers_.clear();
    notice_ = {};
}

bool Session::add_pointer_watch(std::size_t row) {
    if (row >= pointers_.rows().size()) {
        return false;
    }
    if (!target_) {
        set_notice("Сначала выберите процесс", true);
        return false;
    }
    WatchEntry entry = pointers_.watch_entry(row);
    refresh_modules();
    const bool added = watch_.add(std::move(entry));
    set_notice("Цепочка " + pointers_.path_text(row) + (added ? " добавлена в список адресов" : " уже в списке адресов"), false);
    return added;
}

}  // namespace mh::gui
