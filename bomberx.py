import requests
import time
import sys
import random
from threading import Thread
from termcolor import colored, cprint

# Target and message variables
target = ""
msg = ""
num = 0
api_key = ""

# Free provider API keys (you need to set these)
sms77_api_key = ""
textemall_api_key = ""

# Counter to track which provider to use
message_counter = 0

def send_textbelt_sms(target, message, api_key):
   """Send SMS using Textbelt API"""
   url = "https://textbelt.com/text"
   payload = {
       'phone': target,
       'message': message,
       'key': api_key
   }

   try:
       response = requests.post(url, data=payload, timeout=10)
       result = response.json()

       if result.get('success'):
           print(colored(f"✓ Textbelt: SMS sent successfully!", 'green', attrs=['bold']))
           print(colored(f"  Remaining quota: {result.get('quotaRemaining')}", 'cyan'))
           return True
       else:
           print(colored(f"✗ Textbelt: Failed to send SMS", 'red', attrs=['bold']))
           print(colored(f"  Error: {result.get('error')}", 'red'))
           return False
   except Exception as e:
       print(colored(f"✗ Textbelt: Error occurred", 'red', attrs=['bold']))
       print(colored(f"  Exception: {str(e)}", 'red'))
       return False

def send_sms77_sms(target, message):
   """Send SMS using real SMS77 provider"""
   if not sms77_api_key:
       print(colored("✗ SMS77: No API key set!", 'red', attrs=['bold']))
       return False

   url = "https://gateway.sms77.io/api/sms"

   # Format the phone number for SMS77 (remove + and add country code)
   phone_formatted = target.replace("+", "").replace(" ", "")

   payload = {
       'p': sms77_api_key,
       'to': phone_formatted,
       'text': message,
       'from': 'BOMBERX',
       'type': 'quality'
   }

   try:
       response = requests.post(url, data=payload, timeout=10)

       if response.text.startswith('100'):
           print(colored(f"✓ SMS77: SMS sent successfully!", 'green', attrs=['bold']))
           return True
       else:
           print(colored(f"✗ SMS77: Failed to send SMS", 'red', attrs=['bold']))
           print(colored(f"  Response: {response.text}", 'red'))
           return False
   except Exception as e:
       print(colored(f"✗ SMS77: Error occurred", 'red', attrs=['bold']))
       print(colored(f"  Exception: {str(e)}", 'red'))

       # Fallback to TextEmAll
       return send_textemall_sms(target, message)

def send_textemall_sms(target, message):
   """Fallback SMS provider - TextEmAll API"""
   if not textemall_api_key:
       print(colored("✗ TextEmAll: No API key set!", 'red', attrs=['bold']))
       return False

   url = "https://api.textemall.com/v1/messages"

   headers = {
       'Authorization': f'Bearer {textemall_api_key}',
       'Content-Type': 'application/json'
   }

   payload = {
       'to': target,
       'message': message
   }

   try:
       response = requests.post(url, json=payload, headers=headers, timeout=10)

       if response.status_code == 200 or response.status_code == 201:
           print(colored(f"✓ TextEmAll: SMS sent successfully!", 'green', attrs=['bold']))
           return True
       else:
           print(colored(f"✗ TextEmAll: Failed to send SMS", 'red', attrs=['bold']))
           print(colored(f"  Status: {response.status_code}", 'red'))
           print(colored(f"  Response: {response.text}", 'red'))
           return False
   except Exception as e:
       print(colored(f"✗ TextEmAll: Error occurred", 'red', attrs=['bold']))
       print(colored(f"  Exception: {str(e)}", 'red'))
       return False

def send_sms(target, message, counter):
   """Send SMS using alternating providers"""
   if counter % 2 == 0:
       return send_textbelt_sms(target, message, api_key)
   else:
       return send_sms77_sms(target, message)

def bomber():
   """Main bombing function"""
   global message_counter

   if not target or not msg or num <= 0:
       print(colored("ERROR: Please set target, message, and number of SMS first!", 'red', attrs=['bold']))
       return

   if not api_key:
       print(colored("ERROR: Please set Textbelt API key first!", 'red', attrs=['bold']))
       return

   print(colored("="*60, 'magenta', attrs=['bold']))
   print(colored("🚀 Starting SMS bombing sequence...", 'yellow', attrs=['bold']))
   print(colored("="*60, 'magenta', attrs=['bold']))
   print(colored(f"📡 Target: {target}", 'cyan', attrs=['bold']))
   print(colored(f"💬 Message: {msg}", 'cyan', attrs=['bold']))
   print(colored(f"🔢 Number of SMS: {num}", 'cyan', attrs=['bold']))
   print(colored(f"🔄 Using alternating providers...", 'green', attrs=['bold']))
   print(colored("="*60, 'magenta', attrs=['bold']))

   sent_count = 0
   failed_count = 0

   for i in range(num):
       message_counter += 1
       print(colored(f"\n📨 Sending SMS #{i+1}/{num}", 'blue', attrs=['bold']))

       success = send_sms(target, msg, message_counter)

       if success:
           sent_count += 1
       else:
           failed_count += 1

       # Wait a bit between messages to avoid rate limiting
       time.sleep(1)

   print(colored("\n" + "="*60, 'magenta', attrs=['bold']))
   print(colored("🎉 Bombing complete!", 'yellow', attrs=['bold']))
   print(colored(f"✅ Sent: {sent_count}", 'green', attrs=['bold']))
   print(colored(f"❌ Failed: {failed_count}", 'red', attrs=['bold']))
   print(colored("="*60, 'magenta', attrs=['bold']))

def main():
   global target, msg, num, api_key, sms77_api_key, textemall_api_key

   print(colored("="*60, 'magenta', attrs=['bold']))
   cprint("💣 SMS BOMBER X - BY ALFI(Django) 💣", 'red', attrs=['bold'])
   print(colored("="*60, 'magenta', attrs=['bold']))
   cprint("Available Commands:", 'yellow', attrs=['bold'])
   print(colored("set target <phone number with country code>", 'cyan'))
   print(colored("set msg <message content>", 'cyan'))
   print(colored("set num <number of SMS>", 'cyan'))
   print(colored("set api <Textbelt API key>", 'cyan'))
   print(colored("set sms77 <SMS77 API key>", 'cyan'))
   print(colored("set textemall <TextEmAll API key>", 'cyan'))
   print(colored("go - Start bombing", 'green', attrs=['bold']))
   print(colored("exit - Quit", 'red', attrs=['bold']))
   print(colored("="*60, 'magenta', attrs=['bold']))

   while True:
       try:
           command = input(colored("BomberX> ", 'red', attrs=['bold'])).strip()

           if command.lower() == "exit":
               cprint("Goodbye, you crazy motherfucker!", 'yellow', attrs=['bold'])
               break
           elif command.lower().startswith("set target"):
               target = command.split(" ", 2)[2]
               cprint(f"🎯 Target set to: {target}", 'green', attrs=['bold'])
           elif command.lower().startswith("set msg"):
               msg = command.split(" ", 2)[2]
               cprint(f"💬 Message set: {msg}", 'cyan', attrs=['bold'])
           elif command.lower().startswith("set num"):
               num = int(command.split(" ", 2)[2])
               cprint(f"🔢 Number of SMS set to: {num}", 'blue', attrs=['bold'])
           elif command.lower().startswith("set api"):
               api_key = command.split(" ", 2)[2]
               cprint(f"🔑 Textbelt API key set", 'green', attrs=['bold'])
           elif command.lower().startswith("set sms77"):
               sms77_api_key = command.split(" ", 2)[2]
               cprint(f"🔑 SMS77 API key set", 'green', attrs=['bold'])
           elif command.lower().startswith("set textemall"):
               textemall_api_key = command.split(" ", 2)[2]
               cprint(f"🔑 TextEmAll API key set", 'green', attrs=['bold'])
           elif command.lower() == "go":
               if not api_key or not sms77_api_key:
                   cprint("ERROR: You must set all API keys first!", 'red', attrs=['bold'])
                   cprint("Use: set api <Textbelt key>", 'red')
                   cprint("Use: set sms77 <SMS77 key>", 'red')
                   cprint("Use: set textemall <TextEmAll key>", 'red')
               else:
                   # Start bombing in a separate thread so we can maintain CLI responsiveness
                   bomber_thread = Thread(target=bomber)
                   bomber_thread.daemon = True
                   bomber_thread.start()
           else:
               cprint("Unknown command. Type 'help' for available commands.", 'yellow', attrs=['bold'])

       except KeyboardInterrupt:
           print(colored("\nInterrupted by user. Exiting...", 'yellow', attrs=['bold']))
           break
       except Exception as e:
           cprint(f"Error: {str(e)}", 'red', attrs=['bold'])

if __name__ == "__main__":
   main()

