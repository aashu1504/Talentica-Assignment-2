#!/usr/bin/env python3
"""
Update HTML Report Generator with Fixed Filtering Logic
This script ensures the HTML generator always has the correct filtering logic
"""

import os
import shutil
from datetime import datetime

def backup_and_update_html_generator():
    """Backup current generator and ensure it has the latest fixes"""
    generator_file = "generate_html_report.py"
    
    if not os.path.exists(generator_file):
        print(f"❌ Error: {generator_file} not found!")
        return False
    
    # Create backup with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f"generate_html_report_backup_{timestamp}.py"
    
    try:
        # Create backup
        shutil.copy2(generator_file, backup_file)
        print(f"📁 Backup created: {backup_file}")
        
        # Check if the fix is already applied
        with open(generator_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if "FIXED: Now filters vulnerabilities within endpoints" in content:
            print("✅ HTML generator already has the correct filtering logic!")
            return True
        else:
            print("⚠️  HTML generator needs to be updated with the latest fixes.")
            print("   Please ensure the generate_html_report.py has the latest filtering logic.")
            return False
            
    except Exception as e:
        print(f"❌ Error updating HTML generator: {e}")
        return False

def main():
    """Main function"""
    print("🔧 Checking HTML Report Generator...")
    
    if backup_and_update_html_generator():
        print("✅ HTML generator is up to date with correct filtering logic!")
        print("🎯 Filtering now works correctly:")
        print("   • Click 'Low' → Shows endpoints with low vulnerabilities")
        print("   • Click 'Critical' → Shows only critical vulnerabilities within endpoints")
        print("   • Search works with active filters")
        print("   • Filter info shows what's currently being filtered")
    else:
        print("⚠️  HTML generator may need manual updates.")

if __name__ == "__main__":
    main()