#pragma once
// https://github.com/marcbutler/libpsafe3/LICENSE

#include <string>

#include "safe.h"

namespace psafe3 {

std::string header_field_as_text(const HeaderField& field);
std::string record_field_as_text(const RecordField& field);

} // namespace psafe3
