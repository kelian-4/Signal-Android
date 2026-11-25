plugins {
  id("signal-library")
}

android {
  namespace = "dev.kelian.mesh.ble"
}

dependencies {
  api(project(":lib:offline-core"))
}
