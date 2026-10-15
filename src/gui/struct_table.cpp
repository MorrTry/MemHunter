#include "gui/struct_table.hpp"

#include <algorithm>

#include "common/text.hpp"

namespace mh::gui {

namespace {

// Nothing is ever mapped below it; a chain that ends there went through a null pointer.
constexpr std::uint64_t kLowestAddress = 0x10000;

}  // namespace

StructStart struct_start(const WatchEntry& entry, unsigned pointer_size) {
    if (!entry.path) {
        return {PointerPath{{}, entry.address, {}, pointer_size}, 0};
    }
    auto [base, offset] = split_field_path(*entry.path);
    if (offset >= kMaxStructSize) {
        base = *entry.path;
        offset = 0;
    }
    base.pointer_size = pointer_size;
    return {std::move(base), offset};
}

FieldType field_type(WatchType type) noexcept {
    switch (type) {
        case WatchType::Ascii: return FieldType::Ascii;
        case WatchType::Utf16: return FieldType::Utf16;
        case WatchType::Bytes: return FieldType::Bytes;
        default: return static_cast<FieldType>(type);
    }
}

void StructTable::open(PointerPath base, std::uint32_t size, std::optional<std::uint32_t> focus) {
    close();
    active_ = true;
    instances_[0] = std::move(base);
    size_ = std::clamp<std::uint32_t>(size, 1, kMaxStructSize);
    if (focus) {
        size_ = std::max(size_, std::min(kMaxStructSize, *focus + 8));
    }
    focus_ = focus;
    Node& root = nodes_[0];
    root.size = size_;
    relayout(0);
    rebuild_rows();
}

void StructTable::close() {
    active_ = false;
    instances_ = {};
    instance_count_ = 1;
    size_ = kDefaultStructSize;
    defined_.clear();
    nodes_.clear();
    next_node_ = 1;
    rows_.clear();
    selected_.reset();
    focus_.reset();
    changed_.clear();
    refreshed_.reset();
}

void StructTable::restart() {
    if (!active_) {
        return;
    }
    if (base().module.empty()) {
        close();
        return;
    }
    std::size_t kept = 1;
    for (std::size_t i = 1; i < instance_count_; ++i) {
        if (!instances_[i].module.empty()) {
            instances_[kept++] = instances_[i];
        }
    }
    instance_count_ = kept;
    for (auto& [id, node] : nodes_) {
        node.live = {};
    }
    changed_.clear();
    refreshed_.reset();
}

void StructTable::set_size(std::uint32_t size) {
    if (!active_) {
        return;
    }
    std::uint32_t least = 1;
    for (const StructField& field : defined_) {
        least = std::max(least, field.end(pointer_size()));
    }
    size_ = std::clamp(size, least, kMaxStructSize);
    nodes_.at(0).size = size_;
    relayout(0);
    nodes_.at(0).guessed = false;
    refreshed_.reset();
    rebuild_rows();
}

void StructTable::set_regions(const std::vector<Region>& regions) {
    modules_ = ModuleMap(regions);
    targets_ = PointerTargets(regions);
}

void StructTable::refresh(const MemorySource& memory, Clock::time_point now) {
    if (!active_) {
        return;
    }
    const unsigned pointer = pointer_size();
    for (auto& [id, node] : nodes_) {
        for (std::size_t i = 0; i < instance_count_; ++i) {
            std::optional<std::uint64_t> at;
            if (id == 0) {
                at = resolve_pointer_path(memory, modules_, instances_[i]);
            } else {
                const StructField pointer_field{node.offset, FieldType::Pointer, 0, {}, false};
                at = field_pointer(pointer_field, nodes_.at(node.parent).live[i].dump, pointer);
            }
            if (at && *at < kLowestAddress) {
                at.reset();
            }
            MemoryDump dump = at ? read_dump(memory, *at, node.size) : MemoryDump{};
            Live& live = node.live[i];
            if (live.read) {
                for (const StructField& field : node.layout) {
                    const auto before = field_bytes(field, live.dump, pointer);
                    const auto after = field_bytes(field, dump, pointer);
                    if (!before.empty() && !after.empty() && !std::equal(before.begin(), before.end(), after.begin(), after.end())) {
                        changed_[{id, field.offset, i}] = now;
                    }
                }
            }
            live = {at, std::move(dump), true};
        }
        if (!node.guessed) {
            relayout(id);
        }
    }
    std::erase_if(changed_, [&](const auto& entry) { return now - entry.second >= kWatchChangeHold; });
    refreshed_ = now;
    rebuild_rows();
}

bool StructTable::due(Clock::time_point now, Clock::duration interval) const {
    return active_ && (!refreshed_ || now - *refreshed_ >= interval);
}

void StructTable::select_row(std::size_t row) {
    if (row < rows_.size()) {
        selected_ = row;
    }
}

void StructTable::move_selection(std::ptrdiff_t delta) {
    if (rows_.empty()) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(rows_.size()) - 1;
    const std::ptrdiff_t from = selected_ ? static_cast<std::ptrdiff_t>(*selected_) : (delta > 0 ? -1 : last + 1);
    selected_ = static_cast<std::size_t>(std::clamp<std::ptrdiff_t>(from + delta, 0, last));
}

const StructRow* StructTable::selected() const {
    return selected_ ? row_at(*selected_) : nullptr;
}

void StructTable::select_offset(std::uint32_t offset) {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        const StructRow& row = rows_[i];
        if (row.node == 0 && row.field.offset <= offset && offset < row.field.end(pointer_size())) {
            selected_ = i;
            return;
        }
    }
}

bool StructTable::add_instance(PointerPath base) {
    if (!active_ || instance_count_ == kMaxInstances) {
        return false;
    }
    base.pointer_size = pointer_size();
    if (std::find(instances_.begin(), instances_.begin() + static_cast<std::ptrdiff_t>(instance_count_), base) !=
        instances_.begin() + static_cast<std::ptrdiff_t>(instance_count_)) {
        return false;
    }
    instances_[instance_count_] = std::move(base);
    for (auto& [id, node] : nodes_) {
        node.live[instance_count_] = {};
    }
    ++instance_count_;
    refreshed_.reset();
    return true;
}

void StructTable::remove_instance(std::size_t index) {
    if (index == 0 || index >= instance_count_) {
        return;
    }
    for (std::size_t i = index; i + 1 < instance_count_; ++i) {
        instances_[i] = std::move(instances_[i + 1]);
        for (auto& [id, node] : nodes_) {
            node.live[i] = std::move(node.live[i + 1]);
        }
    }
    --instance_count_;
    instances_[instance_count_] = {};
    for (auto& [id, node] : nodes_) {
        node.live[instance_count_] = {};
    }
    changed_.clear();
}

std::optional<std::uint64_t> StructTable::address(std::size_t instance) const {
    if (!active_ || instance >= instance_count_) {
        return std::nullopt;
    }
    return nodes_.at(0).live[instance].address;
}

std::optional<std::uint64_t> StructTable::field_address(std::size_t row, std::size_t instance) const {
    const StructRow* at = row_at(row);
    if (at == nullptr || instance >= instance_count_) {
        return std::nullopt;
    }
    const auto start = nodes_.at(at->node).live[instance].address;
    return start ? std::optional(*start + at->field.offset) : std::nullopt;
}

std::string StructTable::value_text(std::size_t row, std::size_t instance) const {
    const StructRow* at = row_at(row);
    if (at == nullptr || instance >= instance_count_) {
        return {};
    }
    const Live& live = nodes_.at(at->node).live[instance];
    return live.read ? format_field_value(at->field, live.dump, modules_, pointer_size()) : std::string();
}

bool StructTable::differs(std::size_t row) const {
    for (std::size_t i = 1; i < instance_count_; ++i) {
        if (differs(row, i)) {
            return true;
        }
    }
    return false;
}

bool StructTable::differs(std::size_t row, std::size_t instance) const {
    const StructRow* at = row_at(row);
    if (at == nullptr || instance == 0 || instance >= instance_count_) {
        return false;
    }
    const Node& node = nodes_.at(at->node);
    if (!node.live[0].read || !node.live[instance].read) {
        return false;
    }
    const auto first = field_bytes(at->field, node.live[0].dump, pointer_size());
    const auto other = field_bytes(at->field, node.live[instance].dump, pointer_size());
    return !std::equal(first.begin(), first.end(), other.begin(), other.end());
}

bool StructTable::recently_changed(std::size_t row, std::size_t instance, Clock::time_point now) const {
    const StructRow* at = row_at(row);
    if (at == nullptr) {
        return false;
    }
    const auto found = changed_.find({at->node, at->field.offset, instance});
    return found != changed_.end() && now - found->second < kWatchChangeHold;
}

bool StructTable::editable(std::size_t row) const {
    const StructRow* at = row_at(row);
    return at != nullptr && at->depth == 0;
}

bool StructTable::define(std::uint32_t offset, FieldType type, std::uint32_t length, std::string name) {
    if (!active_ || offset >= kMaxStructSize) {
        return false;
    }
    if (!has_length(type)) {
        length = 0;
    } else if (length == 0 || length > kMaxFieldLength) {
        return false;
    }
    const StructField field{offset, type, length, std::move(name), true};
    const unsigned pointer = pointer_size();
    if (field.end(pointer) > kMaxStructSize) {
        return false;
    }
    std::erase_if(defined_, [&](const StructField& other) { return other.offset < field.end(pointer) && field.offset < other.end(pointer); });
    defined_.push_back(field);
    std::sort(defined_.begin(), defined_.end(), [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    Node& root = nodes_.at(0);
    const bool grows = field.end(pointer) > size_;
    size_ = std::max(size_, field.end(pointer));
    root.size = size_;
    relayout(0);
    if (grows) {
        root.guessed = false;
        refreshed_.reset();
    }
    rebuild_rows();
    return true;
}

bool StructTable::rename(std::size_t row, std::string name) {
    if (!editable(row)) {
        return false;
    }
    const StructField field = rows_[row].field;
    const auto known = std::find_if(defined_.begin(), defined_.end(), [&](const StructField& other) { return other.offset == field.offset; });
    if (known == defined_.end()) {
        return define(field.offset, field.type, field.length, std::move(name));
    }
    known->name = std::move(name);
    relayout(0);
    rebuild_rows();
    return true;
}

void StructTable::forget(std::size_t row) {
    if (!editable(row)) {
        return;
    }
    const std::uint32_t offset = rows_[row].field.offset;
    std::erase_if(defined_, [&](const StructField& field) { return field.offset == offset; });
    relayout(0);
    rebuild_rows();
}

void StructTable::guess_again() {
    for (auto& [id, node] : nodes_) {
        relayout(id);
    }
    rebuild_rows();
}

StructDefinition StructTable::definition() const {
    return {size_, defined_};
}

void StructTable::set_definition(StructDefinition definition) {
    if (!active_) {
        return;
    }
    const unsigned pointer = pointer_size();
    defined_ = std::move(definition.fields);
    std::sort(defined_.begin(), defined_.end(), [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    std::uint32_t least = 1;
    for (StructField& field : defined_) {
        field.defined = true;
        least = std::max(least, field.end(pointer));
    }
    size_ = std::clamp(definition.size, least, kMaxStructSize);
    Node& root = nodes_.at(0);
    root.size = size_;
    relayout(0);
    root.guessed = false;
    refreshed_.reset();
    rebuild_rows();
}

bool StructTable::expandable(std::size_t row) const {
    const StructRow* at = row_at(row);
    return at != nullptr && at->field.type == FieldType::Pointer && at->depth + 1 < kMaxTreeDepth;
}

bool StructTable::expanded(std::size_t row) const {
    const StructRow* at = row_at(row);
    return at != nullptr && nodes_.at(at->node).children.contains(at->field.offset);
}

void StructTable::toggle(std::size_t row) {
    if (!expandable(row)) {
        return;
    }
    const StructRow at = rows_[row];
    Node& parent = nodes_.at(at.node);
    if (const auto child = parent.children.find(at.field.offset); child != parent.children.end()) {
        erase_node(child->second);
    } else {
        const std::uint32_t id = next_node_++;
        parent.children[at.field.offset] = id;
        Node& node = nodes_[id];
        node.parent = at.node;
        node.offset = at.field.offset;
        node.depth = at.depth + 1;
        node.size = kPointeeSize;
        relayout(id);
        refreshed_.reset();
    }
    rebuild_rows();
}

bool StructTable::dissect(std::size_t row) {
    const StructRow* at = row_at(row);
    if (at == nullptr || at->field.type != FieldType::Pointer) {
        return false;
    }
    std::array<PointerPath, kMaxInstances> bases;
    for (std::size_t i = 0; i < instance_count_; ++i) {
        bases[i] = pointee_path(node_path(at->node, i), at->field.offset);
    }
    if (bases[0].offsets.size() > kMaxPathOffsets) {
        return false;
    }
    const std::size_t count = instance_count_;
    open(std::move(bases[0]), kDefaultStructSize);
    for (std::size_t i = 1; i < count; ++i) {
        instances_[i] = std::move(bases[i]);
    }
    instance_count_ = count;
    return true;
}

PointerPath StructTable::path_to(std::size_t row, std::size_t instance) const {
    const StructRow* at = row_at(row);
    if (at == nullptr || instance >= instance_count_) {
        return {};
    }
    return field_path(node_path(at->node, instance), at->field.offset);
}

std::string StructTable::path_text(std::size_t row, std::size_t instance) const {
    const PointerPath path = path_to(row, instance);
    if (path.module.empty()) {
        if (const auto at = field_address(row, instance)) {
            return format_address(*at);
        }
    }
    return format_pointer_path(path);
}

WatchEntry StructTable::watch_entry(std::size_t row, std::size_t instance) const {
    const StructRow* at = row_at(row);
    if (at == nullptr) {
        return {};
    }
    const StructField& field = at->field;
    WatchType type = WatchType::Bytes;
    if (const auto value = field_value_type(field.type)) {
        type = watch_type(*value);
    } else if (field.type == FieldType::Pointer) {
        type = pointer_size() == 8 ? WatchType::Int64 : WatchType::Int32;
    } else if (field.type == FieldType::Ascii) {
        type = WatchType::Ascii;
    } else if (field.type == FieldType::Utf16) {
        type = WatchType::Utf16;
    }
    std::string description = field.name.empty() ? "+" + format_hex(field.offset) : field.name;
    WatchEntry entry = make_watch_entry(field_address(row, instance).value_or(0), type, field.length, std::move(description));
    PointerPath path = path_to(row, instance);
    if (!path.module.empty() || !path.offsets.empty()) {
        entry.path = std::move(path);
    }
    return entry;
}

std::string StructTable::c_declaration() const {
    if (!active_) {
        return {};
    }
    return mh::c_declaration(defined_.empty() ? std::span<const StructField>(nodes_.at(0).layout) : std::span<const StructField>(defined_),
                             size_, pointer_size());
}

const MemoryDump& StructTable::guess_source(const Node& node) const {
    static const MemoryDump kNothing;
    for (std::size_t i = 0; i < instance_count_; ++i) {
        if (node.live[i].read && node.live[i].dump.any_readable()) {
            return node.live[i].dump;
        }
    }
    return kNothing;
}

void StructTable::relayout(std::uint32_t id) {
    Node& node = nodes_.at(id);
    const MemoryDump& source = guess_source(node);
    node.layout = layout_struct(id == 0 ? std::span<const StructField>(defined_) : std::span<const StructField>(), source, node.size,
                                targets_, pointer_size());
    node.guessed = source.any_readable();
}

void StructTable::erase_node(std::uint32_t id) {
    const Node& node = nodes_.at(id);
    std::vector<std::uint32_t> children;
    for (const auto& [offset, child] : node.children) {
        children.push_back(child);
    }
    for (const std::uint32_t child : children) {
        erase_node(child);
    }
    nodes_.at(node.parent).children.erase(node.offset);
    std::erase_if(changed_, [&](const auto& entry) { return std::get<0>(entry.first) == id; });
    nodes_.erase(id);
}

void StructTable::rebuild_rows() {
    std::vector<std::uint32_t> stale;
    for (const auto& [id, node] : nodes_) {
        for (const auto& [offset, child] : node.children) {
            const bool pointer = std::any_of(node.layout.begin(), node.layout.end(), [&](const StructField& field) {
                return field.offset == offset && field.type == FieldType::Pointer;
            });
            if (!pointer) {
                stale.push_back(child);
            }
        }
    }
    for (const std::uint32_t id : stale) {
        if (nodes_.contains(id)) {
            erase_node(id);
        }
    }

    std::optional<std::pair<std::uint32_t, std::uint32_t>> kept;
    if (const StructRow* row = selected()) {
        kept = std::pair(row->node, row->field.offset);
    }
    rows_.clear();
    const auto add = [&](const auto& self, std::uint32_t id) -> void {
        const Node& node = nodes_.at(id);
        for (const StructField& field : node.layout) {
            rows_.push_back({id, node.depth, field});
            if (const auto child = node.children.find(field.offset); child != node.children.end()) {
                self(self, child->second);
            }
        }
    };
    if (active_) {
        add(add, 0);
    }

    const auto find = [&](std::uint32_t node, std::uint32_t offset, bool inside) -> std::optional<std::size_t> {
        for (std::size_t i = 0; i < rows_.size(); ++i) {
            const StructRow& row = rows_[i];
            if (row.node == node && (row.field.offset == offset ||
                                     (inside && row.field.offset <= offset && offset < row.field.end(pointer_size())))) {
                return i;
            }
        }
        return std::nullopt;
    };
    if (focus_ && active_ && nodes_.at(0).guessed) {
        selected_ = find(0, *focus_, true);
        focus_.reset();
    } else if (kept) {
        const auto found = find(kept->first, kept->second, true);
        selected_ = found ? found : (rows_.empty() ? std::nullopt : std::optional(std::min(*selected_, rows_.size() - 1)));
    } else if (!rows_.empty() && !selected_ && !focus_) {
        selected_ = 0;
    }
    if (selected_ && *selected_ >= rows_.size()) {
        selected_.reset();
    }
}

PointerPath StructTable::node_path(std::uint32_t id, std::size_t instance) const {
    if (id == 0) {
        return instances_[instance];
    }
    const Node& node = nodes_.at(id);
    return pointee_path(node_path(node.parent, instance), node.offset);
}

const StructRow* StructTable::row_at(std::size_t row) const {
    return row < rows_.size() ? &rows_[row] : nullptr;
}

}  // namespace mh::gui
