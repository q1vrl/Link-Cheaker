<?php 


function scanURL($url) {
    $result = [
        'url' => $url,
        'safe' => false,
        'risk_level' => 'low', // low, medium, high
        'risk_score' => 0,
        'warnings' => [],
        'details' => [],
        'api_results' => []
    ];
    
   
    $url = filter_var($url, FILTER_SANITIZE_URL);
    
    // التحقق من صحة الرابط
    if(!filter_var($url, FILTER_VALIDATE_URL)) {
        $result['warnings'][] = "❌ رابط غير صحيح";
        $result['risk_level'] = 'high';
        $result['risk_score'] += 30;
        return $result;
    }
    
    // الفحص المحلي
    performLocalChecks($url, $result);
    
    // الفحص عبر API (محاكاة حالياً)
    performAPIChecks($url, $result);
    
    // تحديد مستوى الخطورة النهائي
    determineRiskLevel($result);
    
    return $result;
}

function performLocalChecks($url, &$result) {
    $parsed_url = parse_url($url);
    
    // فحص البروتوكول
    if(!isset($parsed_url['scheme']) || $parsed_url['scheme'] !== 'https') {
        $result['warnings'][] = "⚠️ يفضل استخدام HTTPS للأمان";
        $result['risk_score'] += 10;
    }
    
    // فحص النطاقات المشبوهة
    $suspicious_domains = [
        'test-malicious.com',
        'phishing-site.com',
        'bad-domain.org'
    ];
    
    if(isset($parsed_url['host']) && in_array($parsed_url['host'], $suspicious_domains)) {
        $result['warnings'][] = "🚨 النطاق مشبوه ومعروف بالاختراقات";
        $result['risk_score'] += 25;
    }
    
    
    if(strlen($url) > 150) {
        $result['warnings'][] = "📏 الرابط طويل جداً - قد يكون خطيراً";
        $result['risk_score'] += 15;
    }
    
    
    if(preg_match('/[<>{}]/', $url)) {
        $result['warnings'][] = "⚡ الرابط يحتوي على أحرف خطيرة";
        $result['risk_score'] += 20;
    }
    
   
    if(substr_count($url, '.') > 5) {
        $result['warnings'][] = "🔍 عدد النقاط في الرابط مريب";
        $result['risk_score'] += 10;
    }
}

function performAPIChecks($url, &$result) {
    // محاكاة فحص Google Safe Browsing
    $google_result = mockGoogleSafeBrowsing($url);
    $result['api_results']['google'] = $google_result;
    
    if(!$google_result['safe']) {
        $result['warnings'][] = "🔒 تم الإبلاغ عن هذا الرابط في قوائم المواقع الخطيرة";
        $result['risk_score'] += 30;
    }
    
    // محاكاة فحص VirusTotal
    $vt_result = mockVirusTotal($url);
    $result['api_results']['virustotal'] = $vt_result;
    
    if($vt_result['positives'] > 0) {
        $result['warnings'][] = "🦠 {$vt_result['positives']} من مضادات الفيروسات صنفت هذا الرابط كخبيث";
        $result['risk_score'] += $vt_result['positives'] * 2;
    }
}

function determineRiskLevel(&$result) {
    if($result['risk_score'] >= 50) {
        $result['risk_level'] = 'high';
        $result['safe'] = false;
    } elseif($result['risk_score'] >= 20) {
        $result['risk_level'] = 'medium';
        $result['safe'] = false;
    } else {
        $result['risk_level'] = 'low';
        $result['safe'] = true;
        $result['details'][] = "✅ جميع الفحوصات سليمة";
    }
    
    $result['details'][] = "📊 درجة الخطورة: {$result['risk_score']}/100";
}

// دوال محاكاة الـ APIs (مؤقتة)
function mockGoogleSafeBrowsing($url) {
    // في الواقع، هنا راح يكون اتصال حقيقي بالـ API
    $malicious_sites = ['bad-site.com', 'phishing-example.com'];
    $host = parse_url($url, PHP_URL_HOST);
    
    return [
        'safe' => !in_array($host, $malicious_sites),
        'message' => in_array($host, $malicious_sites) ? 'موقع خطير' : 'آمن'
    ];
}

function mockVirusTotal($url) {
    // محاكاة نتائج VirusTotal
    $random_positives = rand(0, 5); // لأغراض التجربة
    
    return [
        'positives' => $random_positives,
        'total' => 70,
        'scan_date' => date('Y-m-d H:i:s')
    ];
}

// المعالجة الرئيسية
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['url'])) {
    $url = $_POST['url'];
    $scan_result = scanURL($url);
}
?>
<!DOCTYPE html>
<html lang="ar">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="style.css">
    <title>نتيجة الفحص - Link Checker</title>
</head>
<body class="body">
    <div class="header"> 
        <h1>Link Checker</h1>
        <div class="links">
            <a href="index.html">الرئيسية</a>
            <a href="about.html">من نحن</a>
        </div>
    </div>

    <div class="landing-page">
        <div class="landing-page-left-section" style="width: 100%;">
            <h1>🔍 نتيجة فحص الرابط</h1>
            
            <?php if(isset($scan_result)): ?>
            <div class="result-container">
                <div class="result-header">
                    <h3>📎 الرابط: <?php echo htmlspecialchars($scan_result['url']); ?></h3>
                    <span class="risk-badge risk-<?php echo $scan_result['risk_level']; ?>">
                        مستوى الخطورة: <?php echo $scan_result['risk_level']; ?>
                    </span>
                </div>
                
                <div class="result-status status-<?php echo $scan_result['safe'] ? 'safe' : ($scan_result['risk_level'] == 'medium' ? 'suspicious' : 'danger'); ?>">
                    <?php if($scan_result['safe']): ?>
                        ✅ <strong>الرابط آمن</strong>
                    <?php elseif($scan_result['risk_level'] == 'medium'): ?>
                        ⚠️ <strong>الرابط مشبوه</strong>
                    <?php else: ?>
                        🚨 <strong>الرابط خطير</strong>
                    <?php endif; ?>
                </div>
                
                <?php if(!empty($scan_result['warnings'])): ?>
                <div class="warning-section">
                    <h4>📢 التحذيرات:</h4>
                    <?php foreach($scan_result['warnings'] as $warning): ?>
                        <div class="warning-item"><?php echo $warning; ?></div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
                
                <?php if(!empty($scan_result['details'])): ?>
                <div class="details-section">
                    <h4>📋 التفاصيل:</h4>
                    <?php foreach($scan_result['details'] as $detail): ?>
                        <div class="detail-item"><?php echo $detail; ?></div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
                
                <div class="api-results">
                    <h4>🌐 نتائج الفحص المتقدم:</h4>
                    
                    <div class="api-result">
                        <strong>Google Safe Browsing:</strong>
                        <?php if($scan_result['api_results']['google']['safe']): ?>
                            <span style="color: #28a745;">✅ آمن</span>
                        <?php else: ?>
                            <span style="color: #dc3545;">⛔ خطير</span>
                        <?php endif; ?>
                    </div>
                    
                    <div class="api-result">
                        <strong>VirusTotal Scan:</strong>
                        <span style="color: <?php echo $scan_result['api_results']['virustotal']['positives'] > 0 ? '#dc3545' : '#28a745'; ?>">
                            <?php echo $scan_result['api_results']['virustotal']['positives']; ?>/
                            <?php echo $scan_result['api_results']['virustotal']['total']; ?> 
                            صنفوه خبيث
                        </span>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <a href="index.html" class="btn" style="text-decoration: none; margin: 10px;">فحص رابط آخر</a>
                <button onclick="window.print()" class="btn" style="background: #6c757d;">🖨️ طباعة التقرير</button>
            </div>
            
            <?php else: ?>
            <div class="result-container">
                <p>لم يتم إدخال رابط للفحص.</p>
                <a href="index.html" class="btn" style="text-decoration: none;">العودة للصفحة الرئيسية</a>
            </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html> 