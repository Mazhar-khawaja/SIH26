import os
import json
import importlib.util
import sys
from typing import Dict, Any, Optional
from app.monitoring.logger import get_logger
from app.parsers.base_parser import BaseParser
from app.parsers.plugin_metadata import PluginMetadata

logger = get_logger("ulpf.plugin_loader")

class PluginLoader:
    def __init__(self, plugin_dir: str):
        self.plugin_dir = plugin_dir

    def load_plugins(self) -> Dict[str, Dict[str, Any]]:
        loaded_plugins = {}
        if not os.path.exists(self.plugin_dir):
            return loaded_plugins

        for entry in os.listdir(self.plugin_dir):
            plugin_path = os.path.join(self.plugin_dir, entry)
            if not os.path.isdir(plugin_path):
                continue

            metadata_path = os.path.join(plugin_path, "metadata.json")
            parser_path = os.path.join(plugin_path, "parser.py")

            if not os.path.exists(metadata_path) or not os.path.exists(parser_path):
                continue

            try:
                with open(metadata_path, 'r') as f:
                    metadata_dict = json.load(f)
                metadata = PluginMetadata(**metadata_dict)

                module_name = f"ulpf_plugins.{entry}"
                spec = importlib.util.spec_from_file_location(module_name, parser_path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load spec for {parser_path}")

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                parser_instance = None
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseParser) and attr is not BaseParser:
                        parser_instance = attr()
                        break

                if not parser_instance:
                    raise ValueError(f"No BaseParser subclass found in {parser_path}")

                loaded_plugins[metadata.name] = {
                    "parser": parser_instance,
                    "metadata": metadata,
                    "enabled": metadata.enabled,
                    "priority": metadata.priority
                }
                logger.info(f"Loaded plugin: {metadata.name} v{metadata.version}")

            except Exception as e:
                logger.error(f"Failed to load plugin {entry}", error=str(e))

        return loaded_plugins
