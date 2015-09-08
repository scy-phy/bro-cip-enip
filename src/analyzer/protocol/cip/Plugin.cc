#include "plugin/Plugin.h"
#include "CIP.h"

namespace plugin {
namespace Bro_CIP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("CIP",
		             ::analyzer::cip::CIP_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Bro::CIP";
		config.description = "Common Industrial Protocol analyzer";
		return config;
		}
} plugin;

}
}
