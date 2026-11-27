pluginManagement {
    repositories {
        google {
            content {
                // JetBrains publishes these markers and artifacts to Maven Central.
                // Do not let an unrelated Google Maven lookup block their resolution.
                excludeGroupByRegex("org[.]jetbrains[.]kotlin([.].*)?")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "LineMcpApp"
include(":app")
