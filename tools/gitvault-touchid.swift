// gitvault-touchid: ask macOS for a biometric confirmation.
//
// Prints nothing on stdout when it succeeds and exits 0. On any failure it prints
// a reason on stderr and exits non-zero, so a caller can treat "could not verify"
// and "verified" as the only two outcomes - there is no third state where the
// check is skipped and the caller proceeds anyway.
//
// Why a separate binary and not a library call: LocalAuthentication is an
// Objective-C framework. Shelling out to a small compiled helper keeps GitVault
// free of an FFI surface and makes the check auditable on its own.
//
// What this is and is not:
//   - It confirms a human is present at the moment `gitvault unlock` runs.
//   - It does NOT protect the vault key itself. Any process running as this user
//     can still read the keychain item directly. Protecting the key requires
//     recreating it with a biometric access control, which is a separate step.

import Foundation
import LocalAuthentication

let reason = CommandLine.arguments.count > 1
    ? CommandLine.arguments[1]
    : "GitVault: confirm to open the credential vault"

let context = LAContext()
context.localizedCancelTitle = "Cancel"

var error: NSError?
let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

guard context.canEvaluatePolicy(policy, error: &error) else {
    // Biometrics unavailable (no Touch ID, closed lid, not enrolled). Fall back to
    // the account password rather than silently allowing the operation: an
    // unavailable sensor must not become an open door.
    let fallback = LAPolicy.deviceOwnerAuthentication
    guard context.canEvaluatePolicy(fallback, error: &error) else {
        FileHandle.standardError.write(
            "touchid: no authentication method available: \(error?.localizedDescription ?? "unknown")\n"
                .data(using: .utf8)!)
        exit(2)
    }
    evaluate(context, fallback, reason)
    exit(0)
}

evaluate(context, policy, reason)
exit(0)

func evaluate(_ context: LAContext, _ policy: LAPolicy, _ reason: String) {
    // How long a prompt may sit unanswered before it reads as "nobody is
    // there". An expired prompt is a REFUSAL, never an approval, so a bound
    // cannot grant anything: it only converts a hung caller - an unattended
    // agent stalled on a fingerprint nobody will ever give - into a clean
    // failure it can report.
    let promptWindow: DispatchTimeInterval = .seconds(120)
    let semaphore = DispatchSemaphore(value: 0)
    var ok = false
    var failure: String?

    context.evaluatePolicy(policy, localizedReason: reason) { success, err in
        ok = success
        failure = err?.localizedDescription
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + promptWindow) == .timedOut {
        // Cancel the modal UI and let the evaluation callback settle before
        // exiting, so the prompt does not linger for a dead caller.
        context.invalidate()
        _ = semaphore.wait(timeout: .now() + .seconds(5))
        FileHandle.standardError.write(
            "touchid: not confirmed: no answer within the prompt window\n"
                .data(using: .utf8)!)
        exit(1)
    }

    if !ok {
        FileHandle.standardError.write(
            "touchid: not confirmed: \(failure ?? "cancelled")\n".data(using: .utf8)!)
        exit(1)
    }
}
