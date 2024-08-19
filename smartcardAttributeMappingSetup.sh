#!/bin/bash

JAMFHELPER="/Library/Application Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper"

# Smartcard Attribute Mapping for Local Accounts

# Array to store messages
messages=()

#Short URL for the user to access
shortURL="{{Put your own URL here}}"

# Check for logged in user.
currentUser="$(echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ && ! /loginwindow/ { print $3 }')"
echo "Current User: $currentUser"

#Check for PIVToken disabled in /Library/Preferences/com.apple.security.smartcard
checkForDisabledPIV() {
  # Read the current DisabledTokens array
  disabled_tokens=$(defaults read /Library/Preferences/com.apple.security.smartcard DisabledTokens 2>/dev/null)

  # Check if the array is not empty and contains the .pivtoken entry
  if [[ "$disabled_tokens" == *"com.apple.CryptoTokenKit.pivtoken"* ]]; then
    echo "pivtoken is disabled. Removing it from DisabledTokens."
    messages+=("pivtoken is disabled. Removing it from DisabledTokens.")

    # Remove the .pivtoken entry using PlistBuddy
    sudo /usr/libexec/PlistBuddy -c "Delete :DisabledTokens:com.apple.CryptoTokenKit.pivtoken" /Library/Preferences/com.apple.security.smartcard.plist

  # Re-check the DisabledTokens array to see if it is now empty
  disabled_tokens=$(defaults read /Library/Preferences/com.apple.security.smartcard DisabledTokens 2>/dev/null | tr -d '[:space:]')

  if [[ "$disabled_tokens" != *"com.apple.CryptoTokenKit.pivtoken"* ]]; then
    echo "pivtoken is not disabled."
    messages+=("pivtoken has been verified as enabled.")
  fi

  # Read the DisabledTokens array and count the number of items
  item_count=$(sudo /usr/libexec/PlistBuddy -c "Print :DisabledTokens" /Library/Preferences/com.apple.security.smartcard.plist | grep -v "Array {" | grep -v "}" | wc -l)

  #If the DisabledTokens array is now empty, delete the entire key
  echo "Number of items in DisabledTokens: $item_count"
  if [ $item_count -eq 0 ]; then
    sudo /usr/libexec/PlistBuddy -c "Delete :DisabledTokens" /Library/Preferences/com.apple.security.smartcard.plist 2>/dev/null
    echo "DisabledTokens key removed as it was empty."
    messages+=("DisabledTokens key removed as it was empty.")
  else
    echo "DisabledTokens key retained with remaining entries."
    messages+=("DisabledTokens key retained with remaining entries.")
  fi
  else
    echo "pivtoken is not disabled."
    messages+=("pivtoken has been verified as enabled.")
  fi
}

# Check for pairing
checkForPaired() {
  tokenCheck=$(/usr/bin/dscl . read /Users/"$currentUser" AuthenticationAuthority | grep -c tokenidentity)
  if [[ "$tokenCheck" > 0 ]]; then
    echo "Unpair $currentUser"
    /usr/sbin/sc_auth unpair -u "$currentUser"
  else
    echo "Nothing Paired"
  fi
}

#Disable smart card pairing UI
disablePairingUI() {
  echo "Disabling pairing ui for $currentUser"
  sudo defaults write /Library/Preferences/com.apple.security.smartcard UserPairing -bool NO

  rv=$(sudo defaults read /Library/Preferences/com.apple.security.smartcard UserPairing)

  if ((rv == 0)); then
    echo "Pairing UI disabled"
    messages+=("Pairing UI disabled")
  else
    echo "Pairing UI not disabled"
    messages+=("Pairing UI not disabled")
  fi
}

#Prompt the user to provision certificate and return when done
promptForCert() {
  description="Please provision your certificate by opening Chrome or Edge and visiting:

$shortURL
   
Click on Go to open your browser."
  certButtonClicked=$(sudo -u "$currentUser" "$JAMFHELPER" -windowType utility -title "Certificate Generation" -description "$description" -button1 "Go" -defaultButton 1)

  if [ "$certButtonClicked" -eq 0 ]; then
    echo "User clicked Go"
    echo "Opening Chrome and sleeping for 30 seconds"
    /usr/bin/open -n "/Applications/Google Chrome.app" --args $shortURL &
    sleep 30
  else
    echo "User clicked Cancel"
    exit 0
  fi
}

checkForSuccess() {
  description="Have you successfully provisioned your certificate? 

Don't click on yes until you have completed the axiad setup.

You can move this window to the side until you have finished."
  successfullCert=$(sudo -u "$currentUser" "$JAMFHELPER" -windowType utility -windowPosition ur -title "Certificate Generation" -description "$description" -button1 "Yes" -defaultButton 1)

  if [ "$successfullCert" -eq 0 ]; then
    echo "User clicked Yes"
    prompt
    checkForPaired
    getUPN
    createAltSecId
    createMapping
    checkForDisabledPIV
    disablePairingUI
    resetAuthenticator
    showFinalStatus
    exit 0
  fi
}

prompt() {
  # Check if the smartcard is already inserted
  if [[ $(security list-smartcards 2>/dev/null | grep -c com.apple.pivtoken) -ge 1 ]]; then
    echo "Smartcard already inserted. Skipping prompt."
    return
  fi

  # Start the JAMF Helper prompt in the background
  sudo -u "$currentUser" "$JAMFHELPER" \
    -windowType hud -title "Smartcard Mapping" -description "Please insert your smartcard to begin." \
    -alignDescription center -lockHUD &

  # Store the PID of the JAMF Helper process
  JAMFHELPER_PID=$!

  # Wait until the smartcard is detected
  while [[ $(security list-smartcards 2>/dev/null | grep -c com.apple.pivtoken) -lt 1 ]]; do
    sleep 1
  done

  # Send a TERM signal to allow for a graceful shutdown
  kill "$JAMFHELPER_PID"
  echo "Smartcard detected, prompt closed."
}

getUPN() {
  # Create temporary directory to export certs:
  tmpdir=$(/usr/bin/mktemp -d)

  # Export certs on smartcard to temporary directory:
  /usr/bin/security export-smartcard -e "$tmpdir"

  # Get path to Certificate for PIV Authentication:
  piv_path=$(ls "$tmpdir" | /usr/bin/grep '^Certificate For PIV')

  # Get User Principle Name from Certificate for PIV Authentication:
  UPN="$(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$piv_path" -strparse $(/usr/bin/openssl asn1parse -i -dump -in "$tmpdir/$piv_path" | /usr/bin/awk -F ':' '/X509v3 Subject Alternative Name/ {getline; print $1}') | /usr/bin/awk -F ':' '/UTF8STRING/{print $4}')"
  # echo "UPN: $UPN"

  # Clean up the temporary directory
  /bin/rm -rf $tmpdir
}

createAltSecId() {
  altSecCheck=$(/usr/bin/dscl . -read /Users/"$currentUser" AltSecurityIdentities 2>/dev/null | sed -n 's/.*Kerberos:\([^ ]*\).*/\1/p')
  if [[ "$UPN" = "" ]]; then
    echo "No UPN found for $currentUser"
    messages+=("No UPN found for $currentUser")
  elif [[ "$altSecCheck" = "$UPN" ]]; then
    echo "AltSec is already set to "$UPN""
    messages+=("AltSec is already set to $UPN")
  else
    echo "Adding AltSecurityIdentities"
    /usr/bin/dscl . -append /Users/"$currentUser" AltSecurityIdentities Kerberos:"$UPN"
    messages+=("Successfully added $UPN to $currentUser")
  fi
}

createMapping() {
  if [ -f /private/etc/SmartcardLogin.plist ]; then
    #Delete the existing file
    echo "Deleting existing SmartcardLogin.plist"
    sudo rm /private/etc/SmartcardLogin.plist
    echo "Done deleting SmartcardLogin.plist"
    messages+=("Deleted existing SmartcardLogin.plist")
  else
    echo "SmartcardLogin.plist does not exist."
  fi

  #Now create the file with the right syntax
  echo "Creating SmartcardLogin.plist"
  /bin/cat >"/private/etc/SmartcardLogin.plist" <<'Attr_Mapping'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
     <key>AttributeMapping</key>
     <dict>
          <key>fields</key>
          <array>
               <string>NT Principal Name</string>
          </array>
          <key>formatString</key>
          <string>Kerberos:$1</string>
          <key>dsAttributeString</key>
          <string>dsAttrTypeStandard:AltSecurityIdentities</string>
     </dict>
     <key>TrustedAuthorities</key>
	   <array>
		  <string></string>
	   </array>
     <key>NotEnforcedGroup</key>
     <string></string>
</dict>
</plist>
Attr_Mapping
  echo "Done creating SmartcardLogin.plist"
  messages+=("Successfully added SmartcardLogin.plist file.")
}

resetAuthenticator() {
  echo "Resetting Authenticator Login"
  sudo authchanger -Reset
  echo "Done with reset"
  messages+=("Successfully returned authenticator to macOS Default.")
}

showFinalStatus() {
  description=$(printf "%s\n" "${messages[@]}")
  rv=$(sudo -u "$currentUser" "$JAMFHELPER" -windowType utility -title "MacSecure Complete" -description "$description" -alignDescription center -button1 "Finish")
}

promptForCert
checkForSuccess
