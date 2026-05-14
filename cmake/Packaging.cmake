set(CPACK_PACKAGE_NAME "ToxTunnel")
set(CPACK_PACKAGE_VENDOR "ToxTunnel")
set(CPACK_PACKAGE_VERSION "${TOXTUNNEL_VERSION}")
set(CPACK_PACKAGE_CONTACT "maintainers@toxtunnel.local")
set(CPACK_COMPONENTS_ALL toxtunnel_runtime)

set(CPACK_PACKAGE_FILE_NAME
    "toxtunnel-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    # Debian packages must use Debian architecture names, not CMake's
    # CMAKE_SYSTEM_PROCESSOR values (e.g. x86_64/aarch64).
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
    endif()
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
    # pkgbuild postinstall: install launchd plist and bootstrap (see packaging/macos/postinstall.sh).
    set(CPACK_POSTFLIGHT_TOXTUNNEL_RUNTIME_SCRIPT
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/macos/postinstall.sh")
endif()

if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(CPACK_WIX_UPGRADE_GUID "F8A3B2C1-7D6E-4A5F-9B0C-1E2D3F4A5B6C")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "ToxTunnel")
    # NOTE: packaging/windows/wix-service-patch.xml is staged but DISABLED for now.
    # CPack-WiX in CMake 3.31 hashes component path parts, so the literal
    # `CM_CP_bin.toxtunnel.exe` Id in the patch never matches a generated component
    # and cpack fails. Until we discover the real hashed Id (or rewrite the patch
    # as a CPACK_WIX_EXTRA_SOURCES fragment), users register the service manually
    # via `toxtunnel install-windows-service` after MSI install. See the
    # `install-windows-service` / `uninstall-windows-service` subcommands in
    # cli/main.cpp and the README's Windows install section.
    # list(APPEND CPACK_WIX_PATCH_FILE
    #     "${CMAKE_CURRENT_SOURCE_DIR}/packaging/windows/wix-service-patch.xml")
endif()

include(CPack)
