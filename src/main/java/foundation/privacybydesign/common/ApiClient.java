package foundation.privacybydesign.common;

import com.google.gson.JsonParseException;
import org.irmacard.api.common.ClientQr;
import org.irmacard.api.common.exceptions.ApiErrorMessage;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.util.GsonUtil;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class ApiClient extends org.irmacard.api.common.ApiClient {
	public static ClientQr createApiSession(String server, String jwt) {
		// Post our JWT
		String qrString = ClientBuilder.newClient().target(server)
				.request(MediaType.APPLICATION_JSON_TYPE)
				.post(Entity.entity(jwt, MediaType.TEXT_PLAIN), String.class);

		// Try to parse the output of the server as a QR
		try {
			ClientQr qr = GsonUtil.getGson().fromJson(qrString, ClientQr.class);
			if (qr.getUrl() == null || qr.getUrl().length() == 0
					|| qr.getVersion() == null || qr.getVersion().length() == 0)
				throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);

			qr.setUrl(server + qr.getUrl()); // Let the token know where to find the server
			return qr;
		} catch (JsonParseException e) {
			try {
				// If it is not a QR then it could be an error message from the API server.
				// Try to deserialize it as such; if it is, then we rethrow it to the token
				ApiErrorMessage apiError = GsonUtil.getGson().fromJson(qrString, ApiErrorMessage.class);
				throw new ApiException(apiError.getError(), "Error from issuing server");
			} catch (Exception parseEx) {
				// Not an ApiErrorMessage
				throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
			}
		}
	}
}
