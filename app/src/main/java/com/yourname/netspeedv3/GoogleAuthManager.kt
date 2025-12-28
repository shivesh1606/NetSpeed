package com.yourname.netspeedv3

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.util.Log
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.tasks.Task
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.GoogleAuthProvider

class GoogleAuthManager(private val context: Context) {
    private val auth: FirebaseAuth = FirebaseAuth.getInstance()
    private lateinit var googleSignInClient: GoogleSignInClient

    companion object {
        private const val TAG = "GoogleAuthManager"
        private const val RC_SIGN_IN = 9001
    }

    init {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(context.getString(R.string.default_web_client_id))
            .requestEmail()
            .requestProfile()
            .build()

        googleSignInClient = GoogleSignIn.getClient(context, gso)
    }

    fun signIn(activity: Activity) {
        val signInIntent = googleSignInClient.signInIntent
        activity.startActivityForResult(signInIntent, RC_SIGN_IN)
    }

    fun handleActivityResult(requestCode: Int, resultCode: Int, data: Intent?, onAuthSuccess: () -> Unit, onAuthFailure: (String) -> Unit) {
        if (requestCode == RC_SIGN_IN) {
            val task = GoogleSignIn.getSignedInAccountFromIntent(data)
            handleSignInResult(task, onAuthSuccess, onAuthFailure)
        }
    }

    private fun handleSignInResult(completedTask: Task<GoogleSignInAccount>, onAuthSuccess: () -> Unit, onAuthFailure: (String) -> Unit) {
        try {
            val account = completedTask.getResult(ApiException::class.java)
            Log.d(TAG, "signInResult:success display=${account?.displayName}")
            // FIX: Pass onAuthSuccess and onAuthFailure to the next function
            firebaseAuthWithGoogle(account?.idToken ?: "", onAuthSuccess, onAuthFailure)
        } catch (e: ApiException) {
            Log.w(TAG, "signInResult:failed code=${e.statusCode}", e)
            onAuthFailure("Google sign in failed: ${e.statusCode}")
        }
    }

    // FIX: Add onAuthSuccess and onAuthFailure as parameters
    private fun firebaseAuthWithGoogle(idToken: String, onAuthSuccess: () -> Unit, onAuthFailure: (String) -> Unit) {
        val credential = GoogleAuthProvider.getCredential(idToken, null)
        auth.signInWithCredential(credential)
            .addOnCompleteListener { task ->
                if (task.isSuccessful) {
                    Log.d(TAG, "signInWithCredential:success")
                    // Sign in success, update UI with the signed-in user's information
                    onAuthSuccess()
                } else {
                    Log.w(TAG, "signInWithCredential:failure", task.exception)
                    onAuthFailure("Authentication failed")
                }
            }
    }


    fun signOut(onSignOutComplete: () -> Unit) {
        googleSignInClient.signOut().addOnCompleteListener {
            auth.signOut()
            onSignOutComplete()
        }
    }

    fun isSignedIn(): Boolean {
        return auth.currentUser != null
    }

    fun getCurrentUser() = auth.currentUser
}