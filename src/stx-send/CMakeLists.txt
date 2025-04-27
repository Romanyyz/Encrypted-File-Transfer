add_executable(stx-send
    main.cpp
)

target_link_libraries(stx-send
    PRIVATE
    common
    compile_flags
)
