package ai.snitchtt.sample

import android.animation.ValueAnimator
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import ai.snitchtt.Snitchtt
import ai.snitchtt.ThreatReport
import ai.snitchtt.sample.databinding.ActivityMainBinding
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: ThreatAdapter
    private val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        adapter = ThreatAdapter(emptyList())
        binding.rvThreats.layoutManager = LinearLayoutManager(this)
        binding.rvThreats.addItemDecoration(DividerItemDecoration(this, DividerItemDecoration.VERTICAL))
        binding.rvThreats.adapter = adapter

        binding.btnScan.setOnClickListener { runScan() }
        runScan()
    }

    private fun runScan() {
        binding.btnScan.isEnabled   = false
        binding.progressBar.visibility = View.VISIBLE
        binding.tvStatus.text       = "Scanning…"

        lifecycleScope.launch {
            val report = Snitchtt.getInstance().scan()
            runOnUiThread { applyReport(report) }
        }
    }

    private fun applyReport(report: ThreatReport) {
        binding.progressBar.visibility = View.GONE
        binding.btnScan.isEnabled      = true
        binding.tvLastScan.text        = "Last scan: ${sdf.format(Date())}"

        animateScore(report.riskScore)

        val (statusText, statusColor, cardColor, labelColor) = when {
            report.isCompromised   -> Quad("COMPROMISED",  R.color.status_compromised, R.color.card_compromised, R.color.on_compromised)
            report.requiresStepUp  -> Quad("SUSPICIOUS",   R.color.status_suspicious,  R.color.card_suspicious,  R.color.on_suspicious)
            else                   -> Quad("CLEAN",        R.color.status_clean,        R.color.card_clean,       R.color.on_clean)
        }

        binding.tvStatus.text = statusText
        binding.tvStatus.setTextColor(ContextCompat.getColor(this, labelColor))
        binding.cardStatus.setCardBackgroundColor(ContextCompat.getColor(this, cardColor))
        binding.tvScoreValue.setTextColor(ContextCompat.getColor(this, labelColor))
        binding.tvScoreLabel.setTextColor(ContextCompat.getColor(this, labelColor))
        binding.tvFlagCount.setTextColor(ContextCompat.getColor(this, labelColor))
        binding.tvFlagCount.text = "${report.flags.size} threat signal${if (report.flags.size != 1) "s" else ""} detected"

        if (report.fridaPort != -1) {
            binding.tvFridaPort.visibility = View.VISIBLE
            binding.tvFridaPort.text = "Frida port: ${report.fridaPort}"
        } else {
            binding.tvFridaPort.visibility = View.GONE
        }

        val sortedFlags = report.flags.sortedByDescending { it.score }
        adapter.update(sortedFlags)

        binding.tvNoThreats.visibility = if (sortedFlags.isEmpty()) View.VISIBLE else View.GONE
        binding.rvThreats.visibility   = if (sortedFlags.isEmpty()) View.GONE    else View.VISIBLE
    }

    private fun animateScore(targetScore: Int) {
        val current = binding.tvScoreValue.tag as? Int ?: 0
        ValueAnimator.ofInt(current, targetScore).apply {
            duration    = 800
            interpolator = AccelerateDecelerateInterpolator()
            addUpdateListener {
                binding.tvScoreValue.text = it.animatedValue.toString()
            }
            start()
        }
        binding.tvScoreValue.tag = targetScore
    }

    private data class Quad(val a: String, val b: Int, val c: Int, val d: Int)
}
