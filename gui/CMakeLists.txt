find_package(Qt6 REQUIRED COMPONENTS Widgets)

set(CMAKE_AUTOMOC ON)

qt_add_executable(spu_iso_gui WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
)

target_link_libraries(spu_iso_gui PRIVATE Qt6::Widgets spucore)

set_target_properties(spu_iso_gui PROPERTIES
    OUTPUT_NAME "spu_iso_gui"
    MACOSX_BUNDLE_BUNDLE_NAME "spu_iso_gui"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.zecoxao.spuisotool"
)

install(TARGETS spu_iso_gui
    RUNTIME DESTINATION bin
    BUNDLE DESTINATION .
)
