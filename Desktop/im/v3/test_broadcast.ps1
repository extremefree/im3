Set-Location C:\Users\wushu\Desktop\im\v3
taskkill /F /IM server.exe /IM client.exe 2>$null | Out-Null
Remove-Item im_users.dat -ErrorAction SilentlyContinue
Start-Process -FilePath ".\server.exe" -NoNewWindow -RedirectStandardOutput "srv_out.txt"
Start-Sleep -Seconds 1

function New-IPv6Client($addr, $port) {
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($addr), $port)
    $tc = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    $tc.Connect($ep); return $tc
}

try {
    # alice connects and logs in
    $ta = New-IPv6Client "::1" 9000
    $sa = $ta.GetStream()
    $sa.ReadTimeout = 3000
    $rb = [byte[]]::new(512)
    $n = $sa.Read($rb, 0, 512)
    Write-Host "ALICE_WELCOME: $([System.Text.Encoding]::UTF8.GetString($rb,0,$n).Trim())"
    $sa.Write([System.Text.Encoding]::UTF8.GetBytes("LOGIN alice:alice123`n"), 0, 21)
    Start-Sleep -Milliseconds 500
    $n = $sa.Read($rb, 0, 512)
    Write-Host "ALICE_LOGIN: $([System.Text.Encoding]::UTF8.GetString($rb,0,$n).Trim())"

    # bob connects and logs in
    $tb = New-IPv6Client "::1" 9000
    $sb = $tb.GetStream()
    $sb.ReadTimeout = 3000
    $rb2 = [byte[]]::new(512)
    $n2 = $sb.Read($rb2, 0, 512)
    Write-Host "BOB_WELCOME: $([System.Text.Encoding]::UTF8.GetString($rb2,0,$n2).Trim())"
    $sb.Write([System.Text.Encoding]::UTF8.GetBytes("LOGIN bob:bob456`n"), 0, 17)
    Start-Sleep -Milliseconds 500
    $n2 = $sb.Read($rb2, 0, 512)
    Write-Host "BOB_LOGIN: $([System.Text.Encoding]::UTF8.GetString($rb2,0,$n2).Trim())"

    # alice sends a message - bob should receive broadcast
    $msg = [System.Text.Encoding]::UTF8.GetBytes("Hello from alice!`n")
    $sa.Write($msg, 0, $msg.Length)
    Start-Sleep -Milliseconds 500
    $n2 = $sb.Read($rb2, 0, 512)
    Write-Host "BOB_RECV: $([System.Text.Encoding]::UTF8.GetString($rb2,0,$n2).Trim())"

    # test /REGISTER
    $tc = New-IPv6Client "::1" 9000
    $sc = $tc.GetStream()
    $sc.ReadTimeout = 3000
    $rb3 = [byte[]]::new(512)
    $n3 = $sc.Read($rb3, 0, 512)
    $sc.Write([System.Text.Encoding]::UTF8.GetBytes("/REGISTER charlie:charlie789`n"), 0, 30)
    Start-Sleep -Milliseconds 500
    $n3 = $sc.Read($rb3, 0, 512)
    Write-Host "REG: $([System.Text.Encoding]::UTF8.GetString($rb3,0,$n3).Trim())"
}
catch { Write-Host "ERR: $_" }
finally {
    if ($ta) { $ta.Close() }
    if ($tb) { $tb.Close() }
    if ($tc) { $tc.Close() }
}

Start-Sleep -Milliseconds 500
Write-Host "=SRV="; Get-Content srv_out.txt
taskkill /F /IM server.exe 2>$null | Out-Null
