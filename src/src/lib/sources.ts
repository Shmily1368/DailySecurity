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

export function getSourceCapabilities(source: SourceConfig): string[] {
  const capabilities = new Set<string>();
  
  // 1. 根据具体 ID 进行精细化多维度映射 (Capability Matrix)
  const id = source.id.toLowerCase();
  
  // -- 综合型大厂安全团队 (既发漏洞预警，也做威胁情报，偶尔发自身公告) --
  if (id.includes('360cert') || id.includes('qianxin') || id.includes('nsfocus') || id.includes('sangfor') || id.includes('dbappsecurity') || id.includes('venustech') || id.includes('topsec') || id.includes('hillstone')) {
    capabilities.add('漏洞预警与深度分析');
    capabilities.add('威胁情报与 APT 追踪');
  }
  
  if (id.includes('tencent_tic')) {
    capabilities.add('威胁情报与 APT 追踪');
    capabilities.add('综合安全资讯与社区');
  }
  
  if (id.includes('threatbook')) {
    capabilities.add('威胁情报与 APT 追踪');
    capabilities.add('漏洞预警与深度分析');
  }
  
  if (id.includes('chaitin') || id.includes('knownsec')) {
    capabilities.add('漏洞预警与深度分析');
  }
  
  // -- 国际顶尖威胁情报与研究团队 --
  if (id.includes('palo_alto_unit42') || id.includes('cisco_talos') || id.includes('mandiant') || id.includes('crowdstrike') || id.includes('microsoft_ti') || id.includes('google_tag') || id.includes('sentinelone') || id.includes('sophos_labs') || id.includes('eset_research') || id.includes('checkpoint_research') || id.includes('elastic_security_labs') || id.includes('kaspersky') || id.includes('rapid7') || id.includes('cloudflare') || id.includes('akamai')) {
    capabilities.add('威胁情报与 APT 追踪');
    capabilities.add('漏洞预警与深度分析'); // 这些团队经常首发 0day/在野利用分析
  }
  
  // -- 官方 CERT 与漏洞库 --
  if (id.includes('cncert') || id.includes('cnvd') || id.includes('cnnvd') || id.includes('cisa') || id.includes('cert_')) {
    capabilities.add('官方应急响应与政策');
    capabilities.add('漏洞预警与深度分析');
  }
  
  if (id.includes('nvd') || id.includes('cve') || id.includes('epss') || id.includes('osv')) {
    capabilities.add('漏洞库与开源生态');
    // NVD/OSV 主要作为基础库，不属于深度分析
  }
  
  // -- 厂商公告专属 (仅发自己产品的更新) --
  if (source.category === 'product_vendor' || source.category === 'cloud_provider' || source.category === 'internet_company') {
    if (!id.includes('tic') && !id.includes('360cert') && !id.includes('qianxin') && !id.includes('nsfocus') && !id.includes('sangfor')) {
      capabilities.add('官方厂商安全公告');
    }
  }
  
  // -- 安全社区与媒体 --
  if (id.includes('freebuf') || id.includes('anquanke') || id.includes('xianzhi') || id.includes('kanxue') || id.includes('bleeping_computer') || id.includes('the_hacker_news') || id.includes('security_week') || id.includes('sans_isc')) {
    capabilities.add('综合安全资讯与社区');
    capabilities.add('威胁情报与 APT 追踪'); // 媒体经常转载情报
  }
  
  // 2. 如果以上没有匹配到，则根据原有的 category 做兜底映射
  if (capabilities.size === 0) {
    const cat = (source.category || '').toLowerCase();
    switch (cat) {
      case 'product_vendor':
      case 'cloud_provider':
      case 'internet_company':
        capabilities.add('官方厂商安全公告');
        break;
      case 'security_vendor':
      case 'threat_research_lab':
        capabilities.add('漏洞预警与深度分析');
        break;
      case 'government_cert':
        capabilities.add('官方应急响应与政策');
        break;
      case 'open_source':
      case 'platform_security':
        capabilities.add('漏洞库与开源生态');
        break;
      case 'threat_intel':
        capabilities.add('威胁情报与 APT 追踪');
        break;
      case 'research_paper':
      case 'academic':
        capabilities.add('学术论文与前沿研究');
        break;
      case 'security_community':
      case 'media':
        capabilities.add('综合安全资讯与社区');
        break;
      default:
        capabilities.add('综合安全资讯与社区');
    }
  }
  
  return Array.from(capabilities);
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
