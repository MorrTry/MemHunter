#include <iostream>
#include <new>

#include "cli/commands.hpp"
#include "cli/console.hpp"

int main() {
    const mh::cli::ConsoleSession console;
    try {
        return mh::cli::run(mh::cli::utf8_arguments(), console);
    } catch (const mh::Error& error) {
        std::cerr << "memhunter: " << error.what() << '\n';
        if (error.code() == mh::ErrorCode::InvalidArgument) {
            std::cerr << "Run 'memhunter help' for usage.\n";
        }
        return mh::cli::exit_code_for(error.code());
    } catch (const std::bad_alloc&) {
        std::cerr << "memhunter: out of memory; try fewer --threads, a smaller --chunk-size or a lower --max-matches\n";
        return mh::cli::kExitInternal;
    } catch (const std::exception& error) {
        std::cerr << "memhunter: internal error: " << error.what() << '\n';
        return mh::cli::kExitInternal;
    }
}
