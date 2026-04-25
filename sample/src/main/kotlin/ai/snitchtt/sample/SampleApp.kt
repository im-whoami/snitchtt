package ai.snitchtt.sample

import android.app.Application
import ai.snitchtt.Snitchtt
import ai.snitchtt.SnitchConfig

class SampleApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Snitchtt.init(
            context = this,
            config  = SnitchConfig(
                checkFridaMaps        = true,
                checkFridaTracer      = true,
                checkFridaPort        = true,
                checkFridaStack       = true,
                checkFridaFd          = true,
                checkMounts           = true,
                checkRoot             = true,
                checkPltHooks         = true,
                checkEnv              = true,
                checkTimingAnomaly    = true,
                checkXposed           = true,
                checkAdb              = true,
                checkBuildSpoof       = true,
                enableContinuousMonitor = false
            )
        )
    }
}
