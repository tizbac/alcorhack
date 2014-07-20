project(alcorhack)
FIND_PACKAGE( Boost 1.40 COMPONENTS program_options REQUIRED )
include_directories(./sg3 ${Boost_INCLUDE_DIR})
add_definitions(-DHAVE_LINUX_BSG_H)
add_library ( sglib STATIC sg3/sg_cmds_basic2.c  sg3/sg_lib.c         
sg3/sg_cmds_basic.c   sg3/sg_lib_data.c    
sg3/sg_cmds_extra.c   sg3/sg_pt_common.c   
sg3/sg_cmds_mmc.c     
sg3/sg_io_linux.c     sg3/sg_pt_linux.c )

add_executable(alcorhack main.cpp)
target_link_libraries( alcorhack sglib ${Boost_LIBRARIES})
install(TARGETS alcorhack RUNTIME DESTINATION bin)
