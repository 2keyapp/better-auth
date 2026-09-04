import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Query param the client puts on `callbackURL` and requires on the `?cookie=` redirect.
const kCallbackNonceParam = 'ba_nonce';

/// 32-byte URL-safe nonce (no padding).
String generateCallbackNonce([Random? random]) {
	final rng = random ?? Random.secure();
	final bytes = Uint8List(32);
	for (var i = 0; i < bytes.length; i++) {
		bytes[i] = rng.nextInt(256);
	}
	return base64Url.encode(bytes).replaceAll('=', '');
}

/// Appends [kCallbackNonceParam] when the URI does not already have one.
Uri withCallbackNonce(Uri callback, {String? nonce}) {
	final existing = callback.queryParameters[kCallbackNonceParam]?.trim() ?? '';
	if (existing.isNotEmpty) return callback;
	final next = Map<String, String>.from(callback.queryParameters);
	next[kCallbackNonceParam] = nonce ?? generateCallbackNonce();
	return callback.replace(queryParameters: next);
}

/// True when [actual] echoes the nonce registered on [expected].
bool callbackNonceMatches({required Uri expected, required Uri actual}) {
	final want = expected.queryParameters[kCallbackNonceParam]?.trim() ?? '';
	final got = actual.queryParameters[kCallbackNonceParam]?.trim() ?? '';
	return want.isNotEmpty && got.isNotEmpty && want == got;
}
