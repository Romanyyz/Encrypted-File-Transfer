add_executable(stx-recv
    main.cpp
    connection.cpp
    connection_manager.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED liburing)

target_link_libraries(stx-recv
    PRIVATE
    common
    compile_flags
    ${LIBURING_LIBRARIES}
)

