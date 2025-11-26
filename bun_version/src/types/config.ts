export interface DatabaseConfig {
  TYPE?: string;
  NAME?: string;
  HOST?: string;
  USER?: string;
  PASSWORD?: string;
  PORT?: number;
}

export interface ModuleConfig {
  [key: string]: any;
}

export interface XeolConfig {
  ENABLED?: boolean;
  DATABASE_PATH?: string;
  AUTO_DOWNLOAD?: boolean;
  DOWNLOAD_URL?: string;
}

export interface Config {
  DATABASE_CONNECTION: {
    TYPE: string;
  };
  VULN_DATABASE: DatabaseConfig;
  PRODUCT_DATABASE: DatabaseConfig;
  XEOL_DATABASE?: XeolConfig;
  RECAPTCHA_AND_API?: {
    ENABLED: boolean;
    SITE_KEY_V3?: string;
    SECRET_KEY_V3?: string;
    SITE_KEY_V2?: string;
    SECRET_KEY_V2?: string;
    API_REQUESTS_RATE_LIMIT_WINDOW?: number;
    API_REQUESTS_RATE_LIMIT_COUNT?: number;
    DATABASE_NAME?: string;
  };
  MODULES: Record<string, ModuleConfig>;
  MODULES_DATA_PREFERENCE: string[];
}

export const DEFAULT_CONFIG: Config = {
  DATABASE_CONNECTION: {
    TYPE: 'sqlite',
  },
  VULN_DATABASE: {
    NAME: 'resources/vulndb.db3',
  },
  PRODUCT_DATABASE: {
    NAME: 'resources/productdb.db3',
  },
  XEOL_DATABASE: {
    ENABLED: false,
    DATABASE_PATH: 'resources/xeol.db',
    AUTO_DOWNLOAD: false,
    DOWNLOAD_URL: 'https://data.xeol.io/xeol/databases/listing.json',
  },
  RECAPTCHA_AND_API: {
    ENABLED: false,
    API_REQUESTS_RATE_LIMIT_WINDOW: 300,
    API_REQUESTS_RATE_LIMIT_COUNT: 60,
    DATABASE_NAME: 'resources/search_vulns_api.db3',
  },
  MODULES: {
    'cpe_search.search_vulns_cpe_search': {
      NVD_API_KEY: '',
      CPE_SEARCH_COUNT: 10,
      CPE_SEARCH_THRESHOLD: 0.68,
    },
    'nvd.search_vulns_nvd': {
      NVD_API_KEY: '',
    },
    'vulncheck.search_vulns_nvdpp': {
      VULNCHECK_API_KEY: '',
    },
  },
  MODULES_DATA_PREFERENCE: ['nvd.search_vulns_nvd', 'vulncheck.search_vulns_nvdpp'],
};
