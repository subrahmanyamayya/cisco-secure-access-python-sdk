## Project Structure

The SDK is organized into the following key directories:

### `secure_access/`

The main SDK package containing:

- **`api/`** - API client modules for each Cisco Secure Access endpoint. Each file corresponds to a specific API resource (e.g., `access_rules_api.py`, `destination_lists_api.py`, `roaming_computers_api.py`). These modules provide methods to interact with their respective API endpoints.

- **`models/`** - Python data models representing API request and response objects. These classes define the structure of data exchanged with the Cisco Secure Access API, providing type hints and validation.

- **`api_client.py`** - Core API client that handles HTTP communication with the Cisco Secure Access API.

- **`configuration.py`** - Configuration class for setting up authentication, API base URL, and other SDK settings.

- **`exceptions.py`** - Custom exception classes for handling API errors.

- **`rest.py`** - REST client utilities for making HTTP requests.

### `examples/`

Sample scripts demonstrating common use cases and SDK usage patterns. Each example is self-contained and shows how to accomplish specific tasks with the SDK.

### Root Files

- **`openapi-spec.yaml`** - OpenAPI specification for the Cisco Secure Access API
- **`requirements.txt`** - Python dependencies required by the SDK
- **`setup.py`** - Package installation and distribution configuration

## Usage

### SDK Configuration

The SDK uses the `Configuration` class for setup:

```python
from access_token import generate_access_token
from secure_access.configuration import Configuration
from secure_access.api_client import ApiClient

# Generate access token
access_token = generate_access_token()

# Configure SDK
configuration = Configuration(access_token=access_token)
api_client = ApiClient(configuration=configuration)
```

### API Base URL

- Default: `https://api.sse.cisco.com`
- Can be customized via the `host` parameter in `Configuration`

### API Method Variants

Each API endpoint in the `secure_access/api/` modules provides three method variants for different use cases:

1. **Standard Method** (e.g., `add_rule()`):

   - Returns the deserialized response model
   - Automatic validation and type conversion
   - Easiest to use for most cases

   ```python
   rule = api_instance.add_rule(add_rule_request)
   ```

2. **With HTTP Info** (e.g., `add_rule_with_http_info()`):

   - Returns an `ApiResponse` object containing both the data and HTTP response details
   - Access to status codes, headers, and raw response
   - Useful when you need HTTP metadata

   ```python
   api_response = api_instance.add_rule_with_http_info(add_rule_request)
   rule = api_response.data
   status_code = api_response.status_code
   headers = api_response.headers
   ```

3. **Without Preload Content** (e.g., `add_rule_without_preload_content()`):
   - Returns the raw HTTP response without automatic deserialization
   - Skips model validation for better performance
   - Useful for large responses or custom processing
   ```python
   raw_response = api_instance.add_rule_without_preload_content(add_rule_request)
   # Process raw response manually
   ```

## Quick run examples

The `examples/` folder contains sample scripts demonstrating various use cases. For detailed usage of each example, refer to the [README.md](README.md) file.

### Access Token Generation

```bash
python examples/access_token.py
```

### Access Rule Backup and Restore

```bash
python examples/access_rule_backup_restore.py -h
```

### Roaming Computers Backup

```bash
python examples/roaming_computers_backup.py -h
```

### Destination Lists Manager

```bash
python examples/destination_list_manager.py -h
```

### API Key Management

```bash
python examples/key_admin_api.py
```

## API Documentation and Specifications

### API Documentation

- **Latest Cisco API documentation**: https://developer.cisco.com/docs/
- **Cisco Cloud Security documentation**: https://developer.cisco.com/docs/cloud-security/

## Contributing

### Writing Examples for AI Agents

When creating new examples or improving existing ones, follow these guidelines to ensure AI agents can understand and use them effectively:

#### Example Structure

- Each example should be self-contained and executable
- Include clear docstrings explaining the purpose and functionality
- Use descriptive variable names that indicate their purpose
- Add comments explaining complex logic or API-specific behavior

#### Authentication Pattern

Always use the standard authentication pattern:

```python
from access_token import generate_access_token
from secure_access.configuration import Configuration
from secure_access.api_client import ApiClient

# Generate access token using CLIENT_ID and CLIENT_SECRET from environment
access_token = generate_access_token()

# Configure the SDK
configuration = Configuration(access_token=access_token)
api_client = ApiClient(configuration=configuration)
```

#### Error Handling

- Use try-except blocks for API calls
- Catch specific exceptions from `secure_access.exceptions`
- Provide meaningful error messages that help diagnose issues
- Example:

```python
from secure_access.exceptions import ApiException

try:
    response = api_instance.get_access_rules()
except ApiException as e:
    print(f"Error calling API: {e}")
```

#### Command-Line Arguments

- Use `argparse` for command-line interfaces
- Provide `-h/--help` flags with clear descriptions
- Include examples in the help text showing typical usage
- Set sensible defaults where applicable

#### Data Handling

- When working with CSV files or external data, validate input
- Provide clear examples of expected data formats
- Use type hints to indicate expected data types
- Handle pagination properly for large datasets

#### Documentation

- Add a docstring at the top of each example file
- Document all functions with their parameters and return types
- Reference the relevant API endpoint documentation
- Include usage examples in comments or help text

### PR Instructions

- **Security**: Do not commit real credentials or tokens. Use placeholders and document required env vars or files.
  - Never commit `CLIENT_ID` or `CLIENT_SECRET` values
  - Use environment variables for all sensitive data
  - Document any new required environment variables in README.md

### Contribution Conventions

- **Examples contributions**: Contributions for new examples or improvements to existing examples in the `examples/` folder are welcome via pull requests. For changes to SDK core code (`secure_access/` package), please raise an issue or submit a change request first to discuss the proposed changes.
- **Backward compatibility**: Do not change existing sample behavior unless clearly improving or fixing a bug; document changes.
- **Code style**: Follow existing patterns in the `examples/` folder
- **Documentation**: Update README.md when adding new examples or features
- **Error handling**: Include proper exception handling in examples
- **Type hints**: Use type hints for better IDE support and code clarity (see `examples/key_admin_api.py`)
