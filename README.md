# Domain Tracker

A PHP-based domain management tool.
Fetch and saves domain information, DNS records, and with custom properties to local json file.

![Domain Tracker Screenshot](Screenshot%202025-10-15%20181055.png)

## Features

### **Domain Monitoring**
- **WHOIS Data Tracking**: Registrar, creation/expiration dates, nameservers
- **DNS Records**: A, AAAA, MX, CNAME, TXT records
- **Multi-Server DNS Querying**: Google DNS (8.8.8.8), Cloudflare (1.1.1.1), OpenDNS (208.67.222.222) with fallback
- **IPv6 Support**: IPv6 address parsing and validation
- **Cache Indicators**: Visual indicators for cached vs fresh DNS data
- **Automatic Refresh**: Force refresh individual domains bypassing cache

### **Property Management System**
- **Custom Properties**: Create custom tags/categories (max 256 alphanumeric characters)
- **Domain Grouping**: Assign multiple properties to domains for organization
- **Click-to-Select**: Select domains by clicking table rows
- **Property Assignment**: Interface for assigning/removing properties
- **Persistent Properties**: Properties preserved during domain refreshes
- **Bulk Property Management**: Add, edit, and delete properties across all domains

### **User Interface**
- **Responsive Design**: Mobile and desktop compatible interface
- **Sortable Columns**: Click column headers to sort data
- **Field Visibility**: Toggle display of specific data fields
- **AJAX Updates**: Asynchronous property management
- **Color-coded Indicators**: Visual feedback for data freshness and fallback status
- **Domain Selection**: Table-based domain identification and selection

### **Security Features**
- **Input Validation**: Domain name validation (RFC compliant)
- **Data Sanitization**: Protection against malicious input
- **DNS Server Validation**: Whitelisted DNS servers for external queries
- **Record Type Whitelisting**: Only allowed DNS record types processed
- **Local-optimized Security**: Designed for secure local development use

## Installation

### Requirements
- PHP 7.4+ (tested with PHP 8.2)
- Web server (Apache, Nginx, or PHP built-in server)
- JSON extension (typically included)
- Network access for DNS/WHOIS queries

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/domain-tracker.git
   cd domain-tracker
   ```

2. **Start the PHP development server:**
   ```bash
   php -S localhost:8000
   ```

3. **Open in browser:**
   ```
   http://localhost:8000
   ```

### File Structure
```
domain-tracker/
├── index.php           # Main application file
├── styles.css          # CSS styling
├── config.xml          # Field configuration
├── domains.json        # Domain data storage
├── properties.json     # Custom properties storage
├── todo-list.md        # Development roadmap
└── README.md           # This file
```

## Usage

### Adding Domains
1. Enter domain name in the top form (e.g., `example.com`)
2. Click "Add Domain" to fetch and store domain information
3. Domain data is automatically populated from WHOIS and DNS queries

### Managing Properties
1. **Create Properties**: Use the "Property Management" section to add custom tags
2. **Assign Properties**: Click any domain row to select it
3. **Assignment Interface**: Use the dropdown to assign properties to selected domains
4. **Remove Properties**: Click the × button next to assigned properties

### Data Management
- **Refresh Domains**: Click "Refresh" to update domain data (preserves properties)
- **Delete Domains**: Click "Delete" to remove domains from tracking
- **Field Visibility**: Use checkboxes to show/hide specific data columns
- **Sorting**: Click column headers to sort by any field

### Property Examples
```
Good property names:
- "To Transfer"
- "Account 1" 
- "Production Sites"
- "Client ABC"
- "Renewal Due"

Invalid property names:
- Special characters: @#$%
- Too long: >256 characters
- Empty names
```

## Technical Details

### DNS Query System
- **Primary Method**: External DNS servers for fresh data
- **Fallback Method**: PHP's built-in DNS functions if external queries fail
- **Caching Strategy**: Local cache with manual refresh capability
- **IPv6 Support**: AAAA record parsing
- **Timeout Handling**: Configurable timeouts for queries

### Data Storage
- **Domains**: JSON format in `domains.json`
- **Properties**: JSON array in `properties.json`
- **Configuration**: XML format in `config.xml`
- **File-based Storage**: JSON and XML file storage

### Security Considerations
This tool is designed for **local development use**:
- Input validation prevents basic injection attacks
- DNS queries use whitelisted servers only
- Domain validation follows RFC standards
- File permissions should be restricted in production environments

## API Endpoints

The application provides several AJAX endpoints:

- `GET /?action=get_data` - Retrieve all domain data
- `GET /?action=get_properties` - Get available properties
- `POST /?action=add_property` - Create new property
- `POST /?action=assign_property` - Assign property to domain
- `POST /?action=remove_property` - Remove property from domain
- `GET /?action=delete_property` - Delete property entirely

## Configuration

### Field Visibility
Edit `config.xml` to customize:
- Available data fields
- Default visibility settings
- Field labels and ordering

### DNS Settings
Modify the DNS server list in `index.php`:
```php
private const DNS_SERVERS = [
    '8.8.8.8',     // Google DNS
    '1.1.1.1',     // Cloudflare
    '208.67.222.222' // OpenDNS
];
```

## Development Roadmap

See `todo-list.md` for planned features:
- [ ] Bulk domain import/export
- [ ] Search and filtering functionality
- [ ] Property-based filtering
- [ ] Enhanced export formats (CSV, JSON, XML)
- [ ] Automated monitoring and alerts

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).
See the LICENSE file for details.

## Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Check existing issues for solutions
- Review the code comments for implementation details

---

**Built for domain management and monitoring**