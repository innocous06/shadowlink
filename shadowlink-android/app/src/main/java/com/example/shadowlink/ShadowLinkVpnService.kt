package com.example.shadowlink

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

class ShadowLinkVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    companion object {
        init {
            System.loadLibrary("shadowlink_core")
        }
    }

    private external fun startTunnel(
        serverIpPort: String,
        tunFd: Int,
        clientPrivKey: String,
        serverPubKey: String
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        if (isRunning.get()) return START_STICKY

        val serverAddr = intent?.getStringExtra("SERVER_ADDR") ?: return START_NOT_STICKY
        val clientPriv = intent.getStringExtra("CLIENT_PRIV") ?: return START_NOT_STICKY
        val serverPub = intent.getStringExtra("SERVER_PUB") ?: return START_NOT_STICKY

        startVpn(serverAddr, clientPriv, serverPub)
        return START_STICKY
    }

    private fun startVpn(serverAddr: String, clientPriv: String, serverPub: String) {
        val builder = Builder()
        builder.addAddress("10.8.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("1.1.1.1")
        builder.addDnsServer("8.8.8.8")
        builder.setSession("ShadowLink")

        try {
            vpnInterface = builder.establish()
            val fd = vpnInterface?.fd ?: throw IllegalStateException("Failed to establish VPN")

            isRunning.set(true)
            
            vpnThread = Thread {
                Log.i("ShadowLinkVpn", "Starting native tunnel on fd $fd")
                startTunnel(serverAddr, fd, clientPriv, serverPub)
                Log.i("ShadowLinkVpn", "Native tunnel exited")
                stopVpn()
            }
            vpnThread?.start()

        } catch (e: Exception) {
            Log.e("ShadowLinkVpn", "VPN establish failed", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning.set(false)
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e("ShadowLinkVpn", "Failed to close VPN interface", e)
        }
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
