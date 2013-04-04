<?php
/* code credite to https://developer.mastercard.com/portal/display/forums/PHP+Payments+Library */

require_once("OAuth.php");



class TestOAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod_RSA_SHA1 {

	public $p12file;
	public $pass;

	function __construct($p12file, $pass) {
		$this->p12file = $p12file;
		$this->pass = $pass;
	}

  	public function fetch_private_cert(&$request) {
	  	$p12cert = array();
		$file = $this->p12file;
		$fd = fopen($file, 'r');
		$p12buf = fread($fd, filesize($file));
		fclose($fd);

		if ( openssl_pkcs12_read($p12buf, $p12cert, $this->pass) )
		{
			return $p12cert[pkey];
		}
		else
		{
			return NULL;
		}
  }

  public function fetch_public_cert(&$request) {
	  	$p12cert = array();
		$file = $this->p12file;
		$fd = fopen($file, 'r');
		$p12buf = fread($fd, filesize($file));
		fclose($fd);

		if ( openssl_pkcs12_read($p12buf, $p12cert, $this->pass) )
		{
			return $p12cert[cert];
		}
		else
		{
			return NULL;;
		}
  }
}



class MCAuthorization {

	protected $url = "https://sandbox.api.mastercard.com/payments/v1/authorization?Format=XML";
	protected $authorizationBody;
	protected $authorizationHeader;

	function __construct($p12file, $pass, $publicKey, $authorizationBody) {

		$consumer = new OAuthConsumer($publicKey,NULL);

		$params = array("oauth_consumer_key"=>$publicKey,
						"oauth_nonce"=>time() . rand(1000, 9999),
						"oauth_timestamp"=>time(),
						"oauth_version"=>"1.0",
						"oauth_body_hash"=>base64_encode(sha1(utf8_encode($authorizationBody),true)),
						"oauth_signature_method"=>"RSA-SHA1")
						;

		$request = new OAuthRequest('POST',$this->url,$params);

		$signatureMethod = new TestOAuthSignatureMethod_RSA_SHA1($p12file, $pass);

		$request->sign_request($signatureMethod,$consumer,NULL);

		$authorizationHeader[0] = $request->to_header();
		$authorizationHeader[1] = "content-type: application/xml";
		$authorizationHeader[2] = "content-length: ".strlen($authorizationBody);

		$this->authorizationBody = $authorizationBody;
		$this->authorizationHeader = $authorizationHeader;
	}

	function getAuthorizationXML() {
		$curl_handle = curl_init();

		curl_setopt($curl_handle,CURLOPT_URL,$this->url);
		curl_setopt($curl_handle,CURLOPT_POST,1);
		curl_setopt($curl_handle,CURLOPT_POSTFIELDS,$this->authorizationBody);
		curl_setopt($curl_handle,CURLOPT_HTTPHEADER,$this->authorizationHeader);
		curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER,FALSE);

		$response = curl_exec($curl_handle);

		curl_close($curl_handle);

		return $response;
	}

}



class MCPurchase {

	protected $url = "https://sandbox.api.mastercard.com/payments/v1/purchase?Format=XML";
	protected $purchaseBody;
	protected $purchaseHeader;

	function __construct($p12file, $pass, $publicKey, $purchaseBody) {

		$consumer = new OAuthConsumer($publicKey,NULL);

		$params = array("oauth_consumer_key"=>$publicKey,
						"oauth_nonce"=>time() . rand(1000, 9999),
						"oauth_timestamp"=>time(),
						"oauth_version"=>"1.0",
						"oauth_body_hash"=>base64_encode(sha1(utf8_encode($purchaseBody),true)),
						"oauth_signature_method"=>"RSA-SHA1")
						;

		$request = new OAuthRequest('POST',$this->url,$params);

		$signatureMethod = new TestOAuthSignatureMethod_RSA_SHA1($p12file, $pass);

		$request->sign_request($signatureMethod,$consumer,NULL);

		$purchaseHeader[0] = $request->to_header();
		$purchaseHeader[1] = "content-type: application/xml";
		$purchaseHeader[2] = "content-length: ".strlen($purchaseBody);

		$this->purchaseBody = $purchaseBody;
		$this->purchaseHeader = $purchaseHeader;

	}

	function getPurchaseXML() {
		$curl_handle = curl_init();

		curl_setopt($curl_handle,CURLOPT_URL,$this->url);
		curl_setopt($curl_handle,CURLOPT_POST,1);
		curl_setopt($curl_handle,CURLOPT_POSTFIELDS,$this->purchaseBody);
		curl_setopt($curl_handle,CURLOPT_HTTPHEADER,$this->purchaseHeader);
		curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER,FALSE);

		$response = curl_exec($curl_handle);

		curl_close($curl_handle);

		return $response;
	}

}



class MCCapture {

	protected $url = "https://sandbox.api.mastercard.com/payments/v1/capture?Format=XML";
	protected $captureBody;
	protected $captureHeader;

	function __construct($p12file, $pass, $publicKey, $captureBody) {

		$consumer = new OAuthConsumer($publicKey,NULL);

		$params = array("oauth_consumer_key"=>$publicKey,
						"oauth_nonce"=>time() . rand(1000, 9999),
						"oauth_timestamp"=>time(),
						"oauth_version"=>"1.0",
						"oauth_body_hash"=>base64_encode(sha1(utf8_encode($captureBody),true)),
						"oauth_signature_method"=>"RSA-SHA1")
						;

		$request = new OAuthRequest('POST',$this->url,$params);

		$signatureMethod = new TestOAuthSignatureMethod_RSA_SHA1($p12file, $pass);

		$request->sign_request($signatureMethod,$consumer,NULL);

		$captureHeader[0] = $request->to_header();
		$captureHeader[1] = "content-type: application/xml";
		$captureHeader[2] = "content-length: ".strlen($captureBody);

		$this->captureBody = $captureBody;
		$this->captureHeader = $captureHeader;

	}

	function getCaptureXML() {
		$curl_handle = curl_init();

		curl_setopt($curl_handle,CURLOPT_URL,$this->url);
		curl_setopt($curl_handle,CURLOPT_POST,1);
		curl_setopt($curl_handle,CURLOPT_POSTFIELDS,$this->captureBody);
		curl_setopt($curl_handle,CURLOPT_HTTPHEADER,$this->captureHeader);
		curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER,FALSE);

		$response = curl_exec($curl_handle);

		curl_close($curl_handle);

		return $response;
	}

}



class MCRefund {

	protected $url = "https://sandbox.api.mastercard.com/payments/v1/refund?Format=XML";
	protected $refundBody;
	protected $refundHeader;

	function __construct($p12file, $pass, $publicKey, $refundBody) {

		$consumer = new OAuthConsumer($publicKey,NULL);

		$params = array("oauth_consumer_key"=>$publicKey,
						"oauth_nonce"=>time() . rand(1000, 9999),
						"oauth_timestamp"=>time(),
						"oauth_version"=>"1.0",
						"oauth_body_hash"=>base64_encode(sha1(utf8_encode($refundBody),true)),
						"oauth_signature_method"=>"RSA-SHA1")
						;

		$request = new OAuthRequest('POST',$this->url,$params);

		$signatureMethod = new TestOAuthSignatureMethod_RSA_SHA1($p12file, $pass);

		$request->sign_request($signatureMethod,$consumer,NULL);

		$refundHeader[0] = $request->to_header();
		$refundHeader[1] = "content-type: application/xml";
		$refundHeader[2] = "content-length: ".strlen($refundBody);

		$this->refundBody = $refundBody;
		$this->refundHeader = $refundHeader;

	}

	function getRefundXML() {
		$curl_handle = curl_init();

		curl_setopt($curl_handle,CURLOPT_URL,$this->url);
		curl_setopt($curl_handle,CURLOPT_POST,1);
		curl_setopt($curl_handle,CURLOPT_POSTFIELDS,$this->refundBody);
		curl_setopt($curl_handle,CURLOPT_HTTPHEADER,$this->refundHeader);
		curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER,FALSE);

		$response = curl_exec($curl_handle);

		curl_close($curl_handle);

		return $response;
	}

}



class MCVoid {

	protected $url = "https://sandbox.api.mastercard.com/payments/v1/void?Format=XML";
	protected $voidBody;
	protected $voidHeader;

	function __construct($p12file, $pass, $publicKey, $voidBody) {

		$consumer = new OAuthConsumer($publicKey,NULL);

		$params = array("oauth_consumer_key"=>$publicKey,
						"oauth_nonce"=>time() . rand(1000, 9999),
						"oauth_timestamp"=>time(),
						"oauth_version"=>"1.0",
						"oauth_body_hash"=>base64_encode(sha1(utf8_encode($voidBody),true)),
						"oauth_signature_method"=>"RSA-SHA1")
						;

		$request = new OAuthRequest('POST',$this->url,$params);

		$signatureMethod = new TestOAuthSignatureMethod_RSA_SHA1($p12file, $pass);

		$request->sign_request($signatureMethod,$consumer,NULL);

		$voidHeader[0] = $request->to_header();
		$voidHeader[1] = "content-type: application/xml";
		$voidHeader[2] = "content-length: ".strlen($voidBody);

		$this->voidBody = $voidBody;
		$this->voidHeader = $voidHeader;

	}

	function getVoidXML() {
		$curl_handle = curl_init();

		curl_setopt($curl_handle,CURLOPT_URL,$this->url);
		curl_setopt($curl_handle,CURLOPT_POST,1);
		curl_setopt($curl_handle,CURLOPT_POSTFIELDS,$this->voidBody);
		curl_setopt($curl_handle,CURLOPT_HTTPHEADER,$this->voidHeader);
		curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER,FALSE);

		$response = curl_exec($curl_handle);

		curl_close($curl_handle);

		return $response;
	}

}