#!/usr/bin/env node

/**
 * AWS Inspector Vulnerability Report Generator
 * 
 * This script retrieves vulnerability data from AWS Inspector and exports it to CSV format.
 * It allows selecting different AWS profiles and filtering vulnerabilities by severity and status.
 */

const { exec } = require('child_process');
const fs = require('fs');
const readline = require('readline');
const path = require('path');

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

/**
 * Get AWS profiles from credentials and config files
 * Reads both ~/.aws/credentials and ~/.aws/config to find all profiles
 * @returns {Promise<string[]>} Array of profile names
 */
function getAwsProfiles() {
  return new Promise((resolve, reject) => {
    try {
      // Determine home directory in a cross-platform way
      const homeDir = process.env.HOME || process.env.USERPROFILE;
      if (!homeDir) {
        throw new Error('Could not determine home directory');
      }
      
      const credentialsPath = path.join(homeDir, '.aws', 'credentials');
      const configPath = path.join(homeDir, '.aws', 'config');
      
      let profiles = new Set();
      
      // Extract profiles from credentials file
      if (fs.existsSync(credentialsPath)) {
        const content = fs.readFileSync(credentialsPath, 'utf8');
        const profileRegex = /\[(.*?)\]/g;
        let match;
        
        while ((match = profileRegex.exec(content)) !== null) {
          profiles.add(match[1]);
        }
      }
      
      // Extract profiles from config file (format: [profile name])
      if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, 'utf8');
        const profileRegex = /\[profile (.*?)\]/g;
        let match;
        
        while ((match = profileRegex.exec(content)) !== null) {
          profiles.add(match[1]);
        }
      }
      
      resolve(Array.from(profiles));
    } catch (error) {
      console.error('Error reading AWS profile files:', error.message);
      reject(error);
    }
  });
}

/**
 * Get available AWS regions
 * @param {string} profile - AWS profile name
 * @returns {Promise<string[]>} Array of region names
 */
async function getAwsRegions(profile) {
  return new Promise((resolve, reject) => {
    const profileArg = profile ? `--profile ${profile}` : '';
    const command = `aws ec2 describe-regions --query "Regions[].RegionName" --output json ${profileArg}`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        // If we can't get regions programmatically, return a default list
        const defaultRegions = [
          'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
          'ap-south-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-southeast-1',
          'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
          'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
          'sa-east-1'
        ];
        console.log('Could not fetch regions. Using default region list.');
        resolve(defaultRegions);
        return;
      }
      
      try {
        const regions = JSON.parse(stdout);
        resolve(regions);
      } catch (parseError) {
        console.error('Failed to parse regions output:', parseError.message);
        // Return default regions as fallback
        const defaultRegions = [
          'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
          'ap-south-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-southeast-1',
          'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
          'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
          'sa-east-1'
        ];
        resolve(defaultRegions);
      }
    });
  });
}

/**
 * Execute an AWS CLI command with proper escaping
 * @param {string} command - AWS CLI command to run
 * @param {string} profile - AWS profile to use
 * @param {string} region - AWS region to use
 * @returns {Promise<object>} Parsed JSON response
 */
function runAwsCommand(command, profile, region) {
  return new Promise((resolve, reject) => {
    // Add profile and region arguments if specified
    const profileArg = profile ? `--profile ${profile}` : '';
    const regionArg = region ? `--region ${region}` : '';
    const fullCommand = `aws ${command} ${profileArg} ${regionArg}`;
    
    // For debugging
    // console.log(`Executing: ${fullCommand}`);
    
    exec(fullCommand, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        console.error('AWS CLI error:', stderr);
        reject(new Error(`AWS CLI error: ${error.message}`));
        return;
      }
      
      if (stderr) {
        console.warn('AWS CLI warning:', stderr);
      }
      
      try {
        // Attempt to parse the JSON response
        const data = JSON.parse(stdout);
        resolve(data);
      } catch (parseError) {
        reject(new Error(`Failed to parse AWS CLI output: ${parseError.message}`));
      }
    });
  });
}

/**
 * Get Inspector findings based on selected criteria
 * @param {string} profile - AWS profile name
 * @param {string} region - AWS region name
 * @param {string} findingType - Type of findings to retrieve (1, 2, or 3)
 * @returns {Promise<Array>} Array of detailed findings
 */
async function getInspectorFindings(profile, region, findingType) {
  try {
    console.log('Building filter criteria...');
    
    // Command structure for each finding type with correct filter parameter names
    // Based on AWS Inspector2 list-findings API documentation
    let criticalFilterCommand = '';
    let highFilterCommand = '';
    
    switch (findingType) {
      case '1': // Priority active weaknesses - Critical
        criticalFilterCommand = `inspector2 list-findings --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"exploitAvailable":[{"comparison":"EQUALS","value":"YES"}]}' --max-results 100`;
        // Priority active weaknesses - High
        highFilterCommand = `inspector2 list-findings --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],"severity":[{"comparison":"EQUALS","value":"HIGH"}],"exploitAvailable":[{"comparison":"EQUALS","value":"YES"}]}' --max-results 100`;
        break;
      case '2': // All active weaknesses - Critical
        criticalFilterCommand = `inspector2 list-findings --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' --max-results 100`;
        // All active weaknesses - High
        highFilterCommand = `inspector2 list-findings --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}],"severity":[{"comparison":"EQUALS","value":"HIGH"}]}' --max-results 100`;
        break;
      case '3': // All closed weaknesses - Critical
        criticalFilterCommand = `inspector2 list-findings --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"CLOSED"}],"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' --max-results 100`;
        // All closed weaknesses - High
        highFilterCommand = `inspector2 list-findings --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"CLOSED"}],"severity":[{"comparison":"EQUALS","value":"HIGH"}]}' --max-results 100`;
        break;
      default:
        throw new Error('Invalid finding type');
    }
    
    console.log('Retrieving findings matching your criteria...');
    
    // Get all findings based on selected criteria
    let allFindings = [];
    
    // First, get the CRITICAL findings
    console.log('Retrieving Critical severity findings...');
    const criticalFindings = await runAwsCommand(criticalFilterCommand, profile, region);
    
    if (criticalFindings && criticalFindings.findings) {
      console.log(`Found ${criticalFindings.findings.length} Critical severity findings.`);
      allFindings = [...criticalFindings.findings];
    }
    
    // Then, get the HIGH findings
    console.log('Retrieving High severity findings...');
    const highFindings = await runAwsCommand(highFilterCommand, profile, region);
    
    if (highFindings && highFindings.findings) {
      console.log(`Found ${highFindings.findings.length} High severity findings.`);
      allFindings = [...allFindings, ...highFindings.findings];
    }
    
    console.log(`Found a total of ${allFindings.length} matching findings.`);
    
    // For Inspector2, we don't need to get additional details as list-findings returns all the data we need
    // The findings already contain all the necessary information
    
    return allFindings;
  } catch (error) {
    console.error('Error retrieving Inspector findings:', error.message);
    throw error;
  }
}

/**
 * Convert findings to CSV format
 * @param {Array} findings - Array of finding objects
 * @returns {string|null} CSV string or null if no findings
 */
function convertToCsv(findings) {
  if (findings.length === 0) return null;
  
  // Define CSV headers
  const headers = [
    'AWS Account ID', 'Severity', 'CVE ID', 'CWEs', 'EPSS Score', 
    'Exploit Available', 'Remediation',
    'Resource Type', 'Resource ID', 'Registry', 'Repository Name', 
    'Image ID', 'Image OS', 'Image Tags', 'Pushed At'
  ];
  
  // Transform each finding to a CSV row
  const rows = findings.map(finding => {
    // Extract package vulnerability details
    const vulnerability = finding.packageVulnerabilityDetails || {};
    const resource = finding.resources && finding.resources.length > 0 ? finding.resources[0] : {};
    
    // Extract CWEs if available
    const vulnerabilityDetails = vulnerability.vulnerabilityDetails || {};
    const cvss = vulnerabilityDetails.cvss || {};
    const cweList = cvss.cweIds || [];
    const cweString = cweList.length > 0 ? cweList.join(', ') : '-';
    
    // Get remediation text
    let remediationText = "Upgrade your installed software packages to the proposed fixed version and release.";
    if (finding.remediation && finding.remediation.recommendation && finding.remediation.recommendation.text) {
        remediationText = finding.remediation.recommendation.text;
    }
    
    // Extract resource details
    let registry = '-', repositoryName = '-', imageId = '-', imageOs = '-', imageTags = '-', pushedAt = '-';
    if (resource.details && resource.details.awsEcrContainerImage) {
        registry = resource.details.awsEcrContainerImage.registry || '-';
        repositoryName = resource.details.awsEcrContainerImage.repositoryName || '-';
        imageId = resource.details.awsEcrContainerImage.imageId || '-';
        imageOs = resource.details.awsEcrContainerImage.imageOs || '-';
        imageTags = (resource.details.awsEcrContainerImage.imageTags || []).join('; ') || '-';
        pushedAt = resource.details.awsEcrContainerImage.pushedAt || '-';
    }
    
    return [
      finding.awsAccountId || '-',
      finding.severity || '-',
      vulnerability.vulnerabilityId || '-',
      cweString,
      vulnerabilityDetails.epss ? (vulnerabilityDetails.epss.score || '-') : '-',
      finding.exploitAvailable || '-',
      remediationText.replace(/,/g, ';'), // Replace commas in text to avoid CSV issues
      resource.type || '-',
      resource.id || '-',
      registry,
      repositoryName,
      imageId,
      imageOs,
      imageTags,
      pushedAt
    ];
  });
  
  // Add headers to the beginning
  rows.unshift(headers);
  
  // Convert rows to properly escaped CSV format
  return rows.map(row => row.map(cell => {
    // Handle null or undefined values
    if (cell === null || cell === undefined) {
      return '';
    }
    
    const cellStr = String(cell);
    
    // Quote cells that contain commas, quotes, or newlines
    if (cellStr.includes(',') || cellStr.includes('"') || cellStr.includes('\n') || cellStr.includes('\r')) {
      return `"${cellStr.replace(/"/g, '""')}"`;
    }
    return cellStr;
  }).join(',')).join('\n');
}

/**
 * Prompt user for selection from a list of options
 * @param {string} question - Question to display
 * @param {Array} options - Array of options
 * @param {Function} validator - Function to validate input
 * @returns {Promise<string>} Selected option
 */
function promptSelection(question, options, validator) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      const validationResult = validator(answer, options);
      if (validationResult.valid) {
        resolve(validationResult.value);
      } else {
        console.log(validationResult.message || 'Invalid selection. Please try again.');
        resolve(promptSelection(question, options, validator));
      }
    });
  });
}

/**
 * Check if a region has AWS Inspector available
 * @param {string} region - AWS region to check
 * @param {string} profile - AWS profile to use
 * @returns {Promise<boolean>} Whether Inspector is available
 */
async function isInspectorAvailableInRegion(region, profile) {
  try {
    // Simple test command to check if Inspector is available
    await runAwsCommand('inspector2 list-findings --max-results 1', profile, region);
    return true;
  } catch (error) {
    // If we get an AccessDeniedException, that means the service exists but we don't have access
    if (error.message.includes('AccessDenied') || error.message.includes('UnauthorizedOperation')) {
      return true;
    }
    // Other errors likely mean the service isn't available
    return false;
  }
}

/**
 * Get region from AWS config or user's AWS_REGION environment variable
 * @param {string} profile - AWS profile name
 * @returns {Promise<string|null>} Default region if found, null otherwise
 */
async function getDefaultRegion(profile) {
  try {
    // First check if there's a region in the environment
    if (process.env.AWS_REGION) {
      return process.env.AWS_REGION;
    }
    
    // Try to get the region from AWS CLI configuration
    const profileArg = profile ? `--profile ${profile}` : '';
    const command = `aws configure get region ${profileArg}`;
    
    return new Promise((resolve) => {
      exec(command, (error, stdout) => {
        if (error || !stdout.trim()) {
          resolve(null);
          return;
        }
        resolve(stdout.trim());
      });
    });
  } catch (error) {
    return null;
  }
}

/**
 * Main function
 */
async function main() {
  try {
    console.log('===== AWS Inspector Vulnerability Report Generator =====\n');
    
    // Get AWS profiles
    console.log('Looking for AWS profiles...');
    const profiles = await getAwsProfiles();
    
    if (profiles.length === 0) {
      console.log('No AWS profiles found. Please configure your AWS CLI first.');
      rl.close();
      return;
    }
    
    // Display available profiles
    console.log('\nAvailable AWS profiles:');
    profiles.forEach((profile, index) => {
      console.log(`${index + 1}. ${profile}`);
    });
    
    // Profile selection validator
    const profileValidator = (answer, profiles) => {
      const index = parseInt(answer) - 1;
      if (isNaN(index) || index < 0 || index >= profiles.length) {
        return { valid: false, message: 'Invalid profile number. Please try again.' };
      }
      return { valid: true, value: profiles[index] };
    };
    
    // Prompt for profile selection
    const selectedProfile = await promptSelection(
      '\nSelect a profile (enter number): ', 
      profiles, 
      profileValidator
    );
    
    console.log(`\nUsing AWS profile: ${selectedProfile}`);
    
    // Get default region from profile
    const defaultRegion = await getDefaultRegion(selectedProfile);
    
    // Get all available AWS regions
    console.log('\nFetching available AWS regions...');
    const allRegions = await getAwsRegions(selectedProfile);
    
    // Prompt for region selection
    console.log('\nAvailable AWS regions:');
    
    // If we have a default region, put it first in the list
    if (defaultRegion && allRegions.includes(defaultRegion)) {
      const defaultIndex = allRegions.indexOf(defaultRegion);
      allRegions.splice(defaultIndex, 1);
      allRegions.unshift(defaultRegion + ' (default)');
    }
    
    allRegions.forEach((region, index) => {
      console.log(`${index + 1}. ${region}`);
    });
    
    // Region selection validator
    const regionValidator = (answer, regions) => {
      const index = parseInt(answer) - 1;
      if (isNaN(index) || index < 0 || index >= regions.length) {
        return { valid: false, message: 'Invalid region number. Please try again.' };
      }
      // If this is the default region with label, remove the label
      let selectedRegion = regions[index];
      if (selectedRegion.includes(' (default)')) {
        selectedRegion = selectedRegion.split(' ')[0];
      }
      return { valid: true, value: selectedRegion };
    };
    
    const selectedRegion = await promptSelection(
      '\nSelect a region (enter number): ', 
      allRegions, 
      regionValidator
    );
    
    console.log(`\nUsing AWS region: ${selectedRegion}`);
    
    // Check if Inspector is available in the selected region
    console.log('\nChecking if Inspector is available in the selected region...');
    const inspectorAvailable = await isInspectorAvailableInRegion(selectedRegion, selectedProfile);
    
    if (!inspectorAvailable) {
      console.log(`AWS Inspector is not available in the ${selectedRegion} region. Please select a different region.`);
      rl.close();
      return;
    }
    
    // Display finding type options
    console.log('\nSelect finding type:');
    console.log('1. Priority active weaknesses (Critical/High severity with exploit available)');
    console.log('2. All active weaknesses (Critical/High severity)');
    console.log('3. All closed weaknesses (Critical/High severity)');
    
    // Finding type validator
    const findingTypeValidator = (answer) => {
      if (!['1', '2', '3'].includes(answer)) {
        return { valid: false, message: 'Please enter 1, 2, or 3.' };
      }
      return { valid: true, value: answer };
    };
    
    // Prompt for finding type selection
    const findingType = await promptSelection(
      '\nSelect finding type (enter number): ', 
      null, 
      findingTypeValidator
    );
    
    const findingTypeLabels = {
      '1': 'Priority active weaknesses',
      '2': 'All active weaknesses',
      '3': 'All closed weaknesses'
    };
    
    console.log(`\nSelected option: ${findingTypeLabels[findingType]}`);
    console.log('\nRetrieving Inspector findings. This may take a few minutes...');
    
    // Get findings based on selection
    const findings = await getInspectorFindings(selectedProfile, selectedRegion, findingType);
    
    if (findings.length > 0) {
      // Convert findings to CSV
      console.log('\nGenerating CSV report...');
      const csv = convertToCsv(findings);
      
      if (!csv) {
        console.log('Error generating CSV content.');
        rl.close();
        return;
      }
      
      // Define file name based on selection
      const typeLabel = {
        '1': 'priority_active',
        '2': 'all_active',
        '3': 'all_closed'
      }[findingType];
      
      const timestamp = new Date().toISOString().replace(/[:]/g, '-').split('.')[0];
      const fileName = `aws_inspector_${typeLabel}_findings_${timestamp}.csv`;
      
      // Write CSV to file
      try {
        fs.writeFileSync(fileName, csv);
        console.log(`\nReport generated successfully: ${fileName}`);
        console.log(`Total findings: ${findings.length}`);
      } catch (writeError) {
        console.error(`Error writing CSV file: ${writeError.message}`);
      }
    } else {
      console.log('No findings to export.');
    }
    
  } catch (error) {
    console.error('\nAn error occurred:', error.message);
  } finally {
    // Always close the readline interface
    rl.close();
  }
}

// Handle process termination
process.on('SIGINT', () => {
  console.log('\nProcess interrupted. Cleaning up...');
  rl.close();
  process.exit(0);
});

// Execute main function
main();