import xml.etree.ElementTree as ET
from typing import Any, Dict
from app.parsers.base_parser import BaseParser

class WindowsEventParser(BaseParser):
    def can_parse(self, log: str) -> bool:
        if "<Event xmlns=" in log and "http://schemas.microsoft.com/win/2004/08/events/event" in log:
            return True
        return False

    def parse(self, log: str) -> Dict[str, Any]:
        parsed = {
            "source_type": "windows:eventlog",
            "vendor": "Microsoft",
            "product": "Windows",
            "raw_event": log,
            "extracted_data": {}
        }

        try:
            root = ET.fromstring(log)
            # Remove namespace for easier searching
            ns = {'win': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            system = root.find('win:System', ns)
            if system is not None:
                event_id = system.find('win:EventID', ns)
                if event_id is not None:
                    parsed["event_type"] = event_id.text

                time_created = system.find('win:TimeCreated', ns)
                if time_created is not None:
                    parsed["timestamp"] = time_created.get('SystemTime')

                computer = system.find('win:Computer', ns)
                if computer is not None:
                    parsed["hostname"] = computer.text

                provider = system.find('win:Provider', ns)
                if provider is not None:
                    parsed["application"] = provider.get('Name')

            event_data = root.find('win:EventData', ns)
            if event_data is not None:
                for data in event_data.findall('win:Data', ns):
                    name = data.get('Name')
                    val = data.text
                    if name:
                        parsed["extracted_data"][name] = val
                        if name == "IpAddress":
                            parsed["source_ip"] = val
                        if name == "IpPort":
                            parsed["source_port"] = val
                        if name == "TargetUserName":
                            parsed["user"] = val

        except Exception:
            pass

        return parsed

    @property
    def name(self) -> str:
        return "windows_event"
