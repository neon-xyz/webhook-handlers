package xyz.neon.WebhookHandling;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class WebhookHandlingApplication {

	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static final String SECRET_KEY = "9FZ9tiHM6I8ApZ3WA2WLud5dQRE9vJkIkOrpv4y207E=";

	public static void main(String[] args) {
		SpringApplication.run(WebhookHandlingApplication.class, args);
	}

	public ResponseEntity<Map<String, String>> response(HttpStatus status, String message) {
		Map<String, String> map = new HashMap();
		map.put("message", message);
		return ResponseEntity.status(status).body(map);
	}

	@PostMapping("/purchase-complete") // payload is documented https://www.neon.xyz/docs/webhooks
	public ResponseEntity<Map<String, String>> purchaseComplete(@RequestBody Map<String, Object> payload, @RequestHeader("X-NEON-DIGEST") String signature) {
		try {
			String json = new ObjectMapper().writeValueAsString(payload);
			String calculatedSignature = calculateHMAC(json);
			if (!calculatedSignature.equals(signature)) {
				return response(HttpStatus.BAD_REQUEST, "HMAC signature is invalid.");
			}

			return response(HttpStatus.CREATED, "Purchase processed");

		} catch (NoSuchAlgorithmException | InvalidKeyException | JsonProcessingException e) {
			System.out.println("Error while calculating HMAC signature: " + e.getMessage());
			return response(HttpStatus.INTERNAL_SERVER_ERROR, "Error while calculating HMAC signature");
		}
	}

	private String calculateHMAC(String message) throws NoSuchAlgorithmException, InvalidKeyException {
		System.out.println(message);
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(), mac.getAlgorithm());

		mac.init(secretKeySpec);
		byte[] signatureBytes = mac.doFinal(message.getBytes());
		return HexUtils.toHexString(signatureBytes);
	}
}
