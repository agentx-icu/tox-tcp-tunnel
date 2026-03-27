set(CPACK_PACKAGE_NAME "ToxTunnel")
set(CPACK_PACKAGE_VENDOR "ToxTunnel")
# Allow CI to override the package version (e.g. from git tag)
if(DEFINED RELEASE_VERSION)
    set(CPACK_PACKAGE_VERSION "${RELEASE_VERSION}")
else()
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
endif()
set(CPACK_PACKAGE_CONTACT "maintainers@toxtunnel.local")
set(CPACK_COMPONENTS_ALL toxtunnel-runtime)

set(CPACK_PACKAGE_FILE_NAME
    "toxtunnel-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsodium23")
    set(CPACK_RPM_PACKAGE_REQUIRES "libsodium")

    # Wire postinst/prerm scripts as DEB/RPM lifecycle hooks
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/postinst;${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/prerm")
    set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/postinst")
    set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/prerm")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(CPACK_GENERATOR "productbuild;TGZ")
endif()

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
endif()

include(CPack)
