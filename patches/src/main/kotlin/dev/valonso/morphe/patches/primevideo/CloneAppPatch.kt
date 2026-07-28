/*
 * Adapted from ajstrick81/morphe-androidtv-patches.
 * Copyright (C) ajstrick81 and contributors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package dev.valonso.morphe.patches.primevideo

import app.morphe.patcher.patch.resourcePatch
import org.w3c.dom.Element

private const val CLONE_SUFFIX = "mod"

/**
 * Renames package-scoped identifiers which must be unique device-wide, allowing
 * the patched app to coexist with a non-removable system Prime Video install.
 */
@Suppress("unused")
val clonePrimeVideoPatch = resourcePatch(
    name = "Clone Prime Video",
    description = "Installs patched Prime Video as a separate .mod app alongside " +
        "a non-removable system installation. The clone has separate app data and login.",
    default = false,
) {
    compatibleWith(PRIME_VIDEO_COMPATIBILITY)

    finalize {
        val packageName = packageMetadata.packageName
        val newPackageName = "$packageName.$CLONE_SUFFIX"
        val providerStringResources = mutableSetOf<String>()
        val permissionRenames = mutableMapOf<String, String>()

        document("AndroidManifest.xml").use { document ->
            document.documentElement.setAttribute("package", newPackageName)

            val permissions = document.getElementsByTagName("permission")

            for (index in 0 until permissions.length) {
                val permission = permissions.item(index) as? Element ?: continue
                val oldName = permission.getAttribute("android:name")
                val newName = when {
                    oldName.startsWith('.') -> continue
                    oldName.startsWith("$packageName.") ->
                        oldName.replaceFirst(packageName, newPackageName)
                    else -> "${newPackageName}_$oldName"
                }
                permission.setAttribute("android:name", newName)
                permissionRenames[oldName] = newName
            }

            val manifestElements = document.getElementsByTagName("*")
            val permissionReferenceAttributes = listOf(
                "android:permission",
                "android:readPermission",
                "android:writePermission",
            )
            for (index in 0 until manifestElements.length) {
                val element = manifestElements.item(index) as? Element ?: continue

                if (
                    element.tagName == "uses-permission" ||
                    element.tagName == "uses-permission-sdk-23"
                ) {
                    permissionRenames[element.getAttribute("android:name")]?.let {
                        element.setAttribute("android:name", it)
                    }
                }

                permissionReferenceAttributes.forEach { attribute ->
                    permissionRenames[element.getAttribute(attribute)]?.let {
                        element.setAttribute(attribute, it)
                    }
                }
            }

            val providers = document.getElementsByTagName("provider")
            for (index in 0 until providers.length) {
                val provider = providers.item(index) as? Element ?: continue
                val authorities =
                    provider.getAttribute("android:authorities").split(';')
                val newAuthorities = authorities.map { authority ->
                    when {
                        authority.startsWith("$packageName.") ->
                            authority.replaceFirst(packageName, newPackageName)
                        authority.startsWith("@string/") -> {
                            providerStringResources.add(
                                authority.removePrefix("@string/"),
                            )
                            authority
                        }
                        else -> "${newPackageName}_$authority"
                    }
                }
                provider.setAttribute(
                    "android:authorities",
                    newAuthorities.joinToString(";"),
                )
            }
        }

        if (providerStringResources.isNotEmpty()) {
            document("res/values/strings.xml").use { document ->
                val children = document.documentElement.childNodes
                for (index in 0 until children.length) {
                    val element = children.item(index) as? Element ?: continue
                    if (element.getAttribute("name") !in providerStringResources) {
                        continue
                    }

                    val authority = element.textContent
                    element.textContent =
                        if (authority.startsWith("$packageName.")) {
                            authority.replaceFirst(packageName, newPackageName)
                        } else {
                            "${newPackageName}_$authority"
                        }
                }
            }
        }

    }
}
