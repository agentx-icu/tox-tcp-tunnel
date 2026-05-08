set(CPACK_PACKAGE_NAME "ToxTunnel")
set(CPACK_PACKAGE_VENDOR "ToxTunnel")
set(CPACK_PACKAGE_VERSION "${TOXTUNNEL_VERSION}")
set(CPACK_PACKAGE_CONTACT "maintainers@toxtunnel.local")
set(CPACK_COMPONENTS_ALL toxtunnel_runtime)

set(CPACK_PACKAGE_FILE_NAME
    "toxtunnel-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    # Portable Linux builds still rely on the system's libsodium package.
    # Keep explicit package-manager metadata so target-distro install tests can
    # resolve the dependency instead of producing a package that installs but
    # fails to start at runtime.
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
    set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local")
endif()

if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(CPACK_WIX_UPGRADE_GUID "F8A3B2C1-7D6E-4A5F-9B0C-1E2D3F4A5B6C")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "ToxTunnel")
endif()

include(CPack)
