#!/usr/bin/env python3
import json

# Load the discovered endpoints
with open('discovered_endpoints.json', 'r') as f:
    data = json.load(f)

endpoints = data['endpoints']

# Analyze parameter detection
total_params = 0
path_params = 0
query_params = 0
body_params = 0

for ep in endpoints:
    total_params += len(ep['parameters']['path_params']) + len(ep['parameters']['query_params']) + len(ep['parameters']['body_params'])
    path_params += len(ep['parameters']['path_params'])
    query_params += len(ep['parameters']['query_params'])
    body_params += len(ep['parameters']['body_params'])

print('Parameter Detection Analysis:')
print(f'Total Parameters: {total_params}')
print(f'Path Parameters: {path_params}')
print(f'Query Parameters: {query_params}')
print(f'Body Parameters: {body_params}')

# Check for template parameters in paths
template_params = 0
for ep in endpoints:
    if '{user_id}' in ep['path']:
        template_params += 1
    if '{book_title}' in ep['path']:
        template_params += 1

print(f'Template Parameters in Paths: {template_params}')

# Check authentication types
auth_types = set()
for ep in endpoints:
    if ep['authentication_type'] != 'None':
        auth_types.add(ep['authentication_type'])

print(f'Authentication Types Detected: {list(auth_types)}') 