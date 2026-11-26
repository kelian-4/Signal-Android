package dev.kelian.mesh.app

import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import dev.kelian.mesh.ble.BatteryOptimization
import dev.kelian.mesh.ble.BleForegroundService
import dev.kelian.mesh.ble.BlePermissions
import dev.kelian.mesh.core.identity.Bip39
import dev.kelian.mesh.core.protocol.toHex
import dev.kelian.mesh.signal.LibsignalIdentity

/**
 * First mesh screen: identity creation (no phone number, no e-mail, no server), 24-word recovery phrase,
 * restore from a phrase, permissions and start of the Bluetooth service.
 */
class MeshMainActivity : Activity() {
    private var pendingStart = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (MeshApp.hasIdentity(this)) showHome() else showWelcome()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun screen(build: LinearLayout.() -> Unit) {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(32), dp(20), dp(20))
            build()
        }
        setContentView(ScrollView(this).apply { addView(col, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT) })
    }

    private fun LinearLayout.title(t: String) = addView(TextView(context).apply { text = t; textSize = 24f; setTypeface(null, Typeface.BOLD); setPadding(0, 0, 0, dp(12)) })
    private fun LinearLayout.body(t: String) = addView(TextView(context).apply { text = t; textSize = 16f; setPadding(0, dp(4), 0, dp(8)) })
    private fun LinearLayout.button(t: String, onClick: () -> Unit): Button {
        val b = Button(context).apply { text = t; setOnClickListener { onClick() } }
        addView(b)
        return b
    }

    // ------------------------------------------------------------------ welcome / identity

    private fun showWelcome(): Unit = screen {
        title("Bienvenue")
        body("Cette messagerie fonctionne sans internet : les messages passent directement de téléphone en téléphone par Bluetooth. Il n'y a ni numéro de téléphone, ni e-mail, ni serveur.")
        val nick = EditText(context).apply { hint = "Ton pseudo (visible par tes contacts)"; inputType = InputType.TYPE_CLASS_TEXT; setSingleLine() }
        addView(nick)
        button("Créer mon identité") {
            val n = nick.text.toString().trim()
            if (n.isEmpty() || n.length > 40) { toast("Choisis un pseudo de 1 à 40 caractères"); return@button }
            val id = LibsignalIdentity.generate()
            MeshApp.saveIdentity(this@MeshMainActivity, id, n)
            showPhrase(id.recoveryPhrase())
        }
        body("")
        button("Restaurer depuis ma phrase de 24 mots") { showRestore() }
    }

    private fun showPhrase(words: List<String>): Unit = screen {
        title("Ta phrase de récupération")
        body("Écris ces 24 mots sur papier, dans l'ordre, et garde-les en lieu sûr. Ils sont le seul moyen de retrouver ton identité si tu perds ou changes de téléphone. Personne ne peut les récupérer pour toi.")
        addView(TextView(context).apply {
            text = words.chunked(4).mapIndexed { r, row -> row.mapIndexed { c, w -> "${r * 4 + c + 1}. $w" }.joinToString("   ") }.joinToString("\n")
            textSize = 16f; typeface = Typeface.MONOSPACE; setTextIsSelectable(false); setPadding(0, dp(8), 0, dp(16))
        })
        button("J'ai noté ma phrase") { showHome() }
    }

    private fun showRestore(): Unit = screen {
        title("Restaurer mon identité")
        body("Saisis les 24 mots séparés par des espaces.")
        val phrase = EditText(context).apply { hint = "mot1 mot2 mot3 …"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS; minLines = 4 }
        val nick = EditText(context).apply { hint = "Ton pseudo"; setSingleLine() }
        addView(phrase); addView(nick)
        button("Restaurer") {
            val n = nick.text.toString().trim()
            if (n.isEmpty()) { toast("Choisis un pseudo"); return@button }
            try {
                val id = LibsignalIdentity.fromPhrase(Bip39.parse(phrase.text.toString()))
                MeshApp.saveIdentity(this@MeshMainActivity, id, n)
                toast("Identité restaurée")
                showHome()
            } catch (e: IllegalArgumentException) {
                toast("Phrase invalide : vérifie les mots et leur ordre")
            }
        }
        button("Retour") { showWelcome() }
    }

    // ------------------------------------------------------------------ home

    private fun showHome(): Unit = screen {
        title("Mesh")
        val id = MeshApp.identity(this@MeshMainActivity)
        val nick = MeshApp.nickname(this@MeshMainActivity) ?: ""
        body("Pseudo : $nick")
        body("Empreinte de ton identité (à comparer en personne) :\n" + (id?.publicKey?.toHex()?.chunked(4)?.joinToString(" ") ?: "indisponible"))
        val status = TextView(context).apply { textSize = 16f; setPadding(0, dp(12), 0, dp(12)) }
        addView(status)
        refreshStatus(status)
        button("Démarrer la messagerie hors ligne") { startMesh(status) }
        button("Arrêter") { BleForegroundService.stop(this@MeshMainActivity); refreshStatus(status) }
        if (!BatteryOptimization.isExempt(this@MeshMainActivity)) {
            body("Pour que les messages arrivent même écran éteint, autorise l'app à ignorer l'optimisation de batterie.")
            button("Autoriser en arrière-plan") { startActivity(BatteryOptimization.requestIntent(this@MeshMainActivity)) }
        }
        body("Prochaines étapes (pas encore disponibles) : ajouter un contact par QR code, discuter, vérifier un contact.")
    }

    private fun refreshStatus(v: TextView) {
        val st = dev.kelian.mesh.ble.MeshHost.runtime?.status
        v.text = if (st == null || !st.running) "Messagerie arrêtée" else
            "Messagerie active · Bluetooth ${if (st.btEnabled) "activé" else "désactivé"} · liens : ${st.readyLinks} · appareils vus : ${st.peersSeen}"
        v.postDelayed({ if (!isDestroyed) refreshStatus(v) }, 2000)
    }

    private fun startMesh(status: TextView) {
        val missing = BlePermissions.missing(this)
        if (missing.isNotEmpty()) {
            pendingStart = true
            requestPermissions(missing.toTypedArray(), REQ_PERMS)
            return
        }
        if (MeshApp.ensureRuntime(this) == null) { toast("Identité introuvable"); return }
        BleForegroundService.start(this)
        refreshStatus(status)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_PERMS || !pendingStart) return
        pendingStart = false
        // notifications are optional; the Bluetooth permissions are not
        val bluetoothDenied = permissions.indices.any { grantResults.getOrNull(it) != PackageManager.PERMISSION_GRANTED && !permissions[it].endsWith("POST_NOTIFICATIONS") }
        if (bluetoothDenied) { toast("Les permissions Bluetooth sont nécessaires"); return }
        showHome()
        toast("Appuie à nouveau sur « Démarrer »")
    }

    private fun toast(t: String) = Toast.makeText(this, t, Toast.LENGTH_LONG).show()

    companion object { private const val REQ_PERMS = 41 }
}
