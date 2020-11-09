#
# Copyright (C) 2015 Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPLv3 included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

CMAKE_MINIMUM_REQUIRED(VERSION "3.0")
PROJECT(SharemindModuleApis VERSION "1.1.0" LANGUAGES C)

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.6 REQUIRED)

FIND_PACKAGE(SharemindCHeaders 1.3.0 REQUIRED)


# ModuleApis:
SET(SHAREMIND_LIBMODAPI_API_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/api_0x1.h"
)
SharemindAddInterfaceLibrary(ModuleApis
    EXPOSE_FILES ${SHAREMIND_LIBMODAPI_API_HEADERS})
TARGET_INCLUDE_DIRECTORIES(ModuleApis
    INTERFACE
        # $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src> # TODO
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
    )
TARGET_LINK_LIBRARIES(ModuleApis INTERFACE Sharemind::CHeaders)
INSTALL(FILES ${SHAREMIND_LIBMODAPI_API_HEADERS}
        DESTINATION "include/sharemind/module-apis"
        COMPONENT "dev")
SharemindCreateCMakeFindFilesForTarget(ModuleApis
    DEPENDENCIES
        "SharemindCHeaders 1.3.0"
    )


# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("dev"
    NAME "sharemind-module-apis-dev"
    DESCRIPTION "Sharemind Module API development headers"
    DEB_SECTION "libdevel"
    DEB_DEPENDS
        "libsharemind-cheaders-dev (>= 1.3.0)"
        "libc6-dev (>= 2.19)"
)
SharemindPackagingFinalize()
