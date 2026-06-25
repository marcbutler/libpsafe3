#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <ostream>

#include "safe.h"

namespace psafe3 {

void header_field_as_text(const HeaderField& field, std::ostream& out);
void record_field_as_text(const RecordField& field, std::ostream& out);

} // namespace psafe3
