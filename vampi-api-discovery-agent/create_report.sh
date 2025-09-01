#!/bin/bash

# VAmPI Security Assessment HTML Report Generator
# This script generates an HTML report from the JSON security assessment data

echo "🔒 VAmPI Security Assessment HTML Report Generator"
echo "=================================================="

# Check if JSON report exists
if [ ! -f "security_assessment_report.json" ]; then
    echo "❌ Error: security_assessment_report.json not found!"
    echo "Please run the security assessment first to generate the JSON report."
    exit 1
fi

# Generate HTML report
echo "📊 Generating HTML report from JSON data..."
python3 generate_html_report.py

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ HTML report generated successfully!"
    echo "📁 Report file: security_assessment_report_*.html"
    echo ""
    echo "🌐 To view the report:"
    echo "   1. Open the HTML file in your web browser"
    echo "   2. Or serve it locally: python3 -m http.server 8000"
    echo ""
    echo "📋 Report features:"
    echo "   • Interactive vulnerability details"
    echo "   • Search and filter functionality"
    echo "   • Executive summary and risk assessment"
    echo "   • Professional styling and responsive design"
else
    echo "❌ Error generating HTML report!"
    exit 1
fi