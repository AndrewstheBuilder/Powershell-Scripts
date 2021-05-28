while( $true ) {
    $Pos = [System.Windows.Forms.Cursor]::Position
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point((($Pos.X) - 100), $Pos.Y)
    Start-Sleep -Seconds 10
    $Pos = [System.Windows.Forms.Cursor]::Position
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point((($Pos.X) + 100), $Pos.Y)
    Start-Sleep -Seconds 10
}
