

<?php 

require_once("PayPass.php");


//Fill in these variables with the appropriate values
	$p12filename = 'MCOpenAPI.p12';
	$password = '';
	$sandboxClientId = 'IHS-UlVGUc8yVfy-vZNoSpxE6VewnL7Qb7Jnfy71d063fcf8!4c504a703166637468336f4337354f4d37325a312b513d3d';

	$merchants = New MCMerchant($p12filename, $password, $sandboxClientId);

	$response = $merchants->getMerchantXML();

	var_dump($response);
	?>