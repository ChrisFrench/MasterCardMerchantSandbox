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

class MCMerchant {

	protected $url = "https://api.mastercard.com/merchants/v1/merchants?Details=Acceptance.Paypass&Format=XML&PageLength=10&PageOffset=1&PostalCode=84101";
	protected $MerchantBody;
	protected $MerchantHeader;

	function __construct($p12file, $pass, $publicKey) {

		$consumer = new OAuthConsumer($publicKey,NULL);
		$MerchantBody = $url;
		$params = array("oauth_consumer_key"=>$publicKey,
						"oauth_nonce"=>time() . rand(1000, 9999),
						"oauth_timestamp"=>time(),
						"oauth_version"=>"1.0",
						"oauth_body_hash"=>base64_encode(sha1(utf8_encode($MerchantBody),true)),
						"oauth_signature_method"=>"RSA-SHA1")
						;

		$request = new OAuthRequest('POST',$this->url,$params);

		$signatureMethod = new TestOAuthSignatureMethod_RSA_SHA1($p12file, $pass);

		$request->sign_request($signatureMethod,$consumer,NULL);

		$MerchantHeader[0] = $request->to_header();
		$MerchantHeader[1] = "content-type: application/xml";
		$MerchantHeader[2] = "content-length: ".strlen($MerchantBody);

		$this->MerchantBody = $MerchantBody;
		$this->MerchantHeader = $MerchantHeader;

	}

	function getMerchantXML() {
		$curl_handle = curl_init();

		curl_setopt($curl_handle,CURLOPT_URL,$this->url);
		curl_setopt($curl_handle,CURLOPT_POST,1);
		curl_setopt($curl_handle,CURLOPT_POSTFIELDS,$this->MerchantBody);
		curl_setopt($curl_handle,CURLOPT_HTTPHEADER,$this->MerchantHeader);
		curl_setopt($curl_handle,CURLOPT_RETURNTRANSFER,TRUE);
		curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER,FALSE);

		$response = curl_exec($curl_handle);

		curl_close($curl_handle);

		return $response;
	}

}