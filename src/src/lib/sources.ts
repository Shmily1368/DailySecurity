import fs from 'node:fs';
import path from 'node:path';

export interface SourceConfig {
  id: string;
  name: string;
  region: string;
  category: string;
  content_type: string;
  source_quality: string;
  parser: string;
  url: string;
  enabled: boolean;
  notes?: string;
  tags?: string[];
  expected_fields?: string[];
  safety_policy?: string;
}

// Simple fallback YAML parser since we can't easily npm install js-yaml in this env right now
// It extracts the list of dicts. We only need simple key-values
export function simpleYamlParser(content: string): SourceConfig[] {
  const sources: SourceConfig[] = [];
  const lines = content.split('\n');
  
  let currentObj: any = null;
  let inSourcesList = false;
  
  for (let line of lines) {
    // skip empty lines or comments
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    
    if (line.startsWith('sources:')) {
      inSourcesList = true;
      continue;
    }
    
    if (!inSourcesList) continue;
    
    // Check if it's a new list item
    if (line.trim().startsWith('- id:')) {
      if (currentObj && currentObj.id) {
        sources.push(currentObj as SourceConfig);
      }
      currentObj = {};
      const val = line.substring(line.indexOf('id:') + 3).trim().replace(/^"|"$/g, '').replace(/^'|'$/g, '');
      currentObj.id = val;
      continue;
    }
    
    // Parse key-value pairs
    if (currentObj) {
      const match = line.match(/^\s+([a-zA-Z0-9_]+):\s+(.+)$/);
      if (match) {
        const key = match[1];
        let val = match[2].trim();
        
        // Remove quotes if present
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.substring(1, val.length - 1);
        } else if (val === 'true') {
          val = true as any;
        } else if (val === 'false') {
          val = false as any;
        }
        
        currentObj[key] = val;
      }
    }
  }
  
  if (currentObj && currentObj.id) {
    sources.push(currentObj as SourceConfig);
  }
  
  return sources;
}

export function getAllSources(): SourceConfig[] {
  const sourcesDir = path.resolve(process.cwd(), '../config/sources');
  const basePath = path.join(sourcesDir, 'base_sources.yml');
  const vendorPath = path.join(sourcesDir, 'vendor_advisories.yml');
  const threatPath = path.join(sourcesDir, 'threat_intel.yml');
  
  let sources: SourceConfig[] = [];
  
  try {
    if (fs.existsSync(basePath)) {
      const baseContent = fs.readFileSync(basePath, 'utf8');
      sources = sources.concat(simpleYamlParser(baseContent));
    }
    
    if (fs.existsSync(vendorPath)) {
      const vendorContent = fs.readFileSync(vendorPath, 'utf8');
      sources = sources.concat(simpleYamlParser(vendorContent));
    }
    
    if (fs.existsSync(threatPath)) {
      const threatContent = fs.readFileSync(threatPath, 'utf8');
      sources = sources.concat(simpleYamlParser(threatContent));
    }
  } catch (error) {
    console.error('Error loading sources YAML:', error);
  }
  
  return sources;
}

export function categoryToGroup(category: string): string {
  const cat = (category || '').toLowerCase();
  switch (cat) {
    case 'product_vendor':
    case 'cloud_provider':
    case 'internet_company':
      return '产品厂商 / 云厂商公告';
      
    case 'security_vendor':
    case 'threat_research_lab':
      return '安全厂商 / 安全研究团队';
      
    case 'government_cert':
      return '政府 / CERT / 漏洞机构';
      
    case 'open_source':
    case 'platform_security':
      return '开源生态 / 平台安全';
      
    case 'threat_intel':
      return '威胁情报研究';
      
    case 'research_paper':
    case 'academic':
      return '学术论文 / 研究前沿';
      
    case 'security_community':
    case 'media':
      return '安全社区 / 媒体';
      
    default:
      return '安全社区 / 媒体';
  }
}

export function normalizeRegionLabel(region: string): string {
  const r = (region || '').toUpperCase();
  switch (r) {
    case 'CN':
      return '中国大陆';
    case 'HK':
      return '中国香港';
    case 'MO':
      return '中国澳门';
    case 'TW':
      return '中国台湾';
    case 'GLOBAL':
      return '全球';
    case 'US':
      return '美国';
    case 'EU':
      return '欧盟';
    case 'JP':
      return '日本';
    case 'UK':
      return '英国';
    default:
      return r || '未知';
  }
}
