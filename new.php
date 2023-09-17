<?php

$apiKey = '3f18fca68723edf9c522153a35626150096ba8299a42ed70d9886175a1019aff';

$googleApiKey = 'AIzaSyB8Nii3n6g8eDGFL5nH4MqjkWk34rL_kqY';

$url = $_POST['url'] ?? '';

if (empty($url)) {
    echo 'Please provide a URL.';
    exit;
}

$apiUrl = 'https://www.virustotal.com/vtapi/v2/url/report';
$params = array(
    'apikey' => $apiKey,
    'resource' => $url
);
$apiUrl .= '?' . http_build_query($params);

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, $apiUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);

if (curl_errno($ch)) {
    echo 'An error occurred while making the VirusTotal API request: ' . curl_error($ch);
    exit;
}

curl_close($ch);

$data = json_decode($response, true);
$textColor = "red";
$textColor1 = "green";
$textColor2 = "orange";
$textSize = "24px";

if ($data && isset($data['response_code'])) {
    $responseCode = $data['response_code'];

    if ($responseCode == 1) {
        $googleApiUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $googleApiKey;
        $threatData = array(
            'client' => array(
                'clientId' => 'your_client_id',
                'clientVersion' => '1.0'
            ),
            'threatInfo' => array(
                'threatTypes' => ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => [
                    array('url' => $url)
                ]
            )
        );

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $googleApiUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($threatData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));

        $googleResponse = curl_exec($ch);

        if (curl_errno($ch)) {
            echo 'An error occurred while making the Google Safe Browsing API request: ' . curl_error($ch);
            exit;
        }

        curl_close($ch);

        $googleData = json_decode($googleResponse, true);

        if ($googleData && isset($googleData['matches']) && !empty($googleData['matches'])) {
            echo "<h2 style=\"color: {$textColor2}; font-size: {$textSize};\">{$url} is flagged as a potentially dangerous URL.</h2>";
        } else {
            echo "<h2 style=\"color: {$textColor1}; font-size: {$textSize};\">{$url} is a safe URL.</h2>";
        }
    } 
    elseif ($responseCode == -1) {
        echo "<h2 style=\"color: {$textColor2}; font-size: {$textSize};\">{$url} is not a safe URL</h2>";
    } 
    else {
        echo "<h2 style=\"color: {$textColor}; font-size: {$textSize};\">{$url}  : An error occurred while checking the URL.";
    }
} 
else {
    echo "<h2 style=\"color: {$textColor}; font-size: {$textSize};\">{$url} : An error occurred while checking the URL.";
}
?>