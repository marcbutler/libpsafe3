add_library(util STATIC ioport.c util.c)
set_property(TARGET util PROPERTY POSITION_INDEPENDENT_CODE ON)
