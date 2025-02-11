add_library(util OBJECT ioport.c util.c)
set_property(TARGET util PROPERTY POSITION_INDEPENDENT_CODE ON)
