// Synthetic fixture (not upstream code) exercising the patterns catalog-gen
// recognises in C++ sources.
#define REGISTER_FAKE_STAGE(key, parser) REGISTER_DOCUMENT_SOURCE(key, parser)
#define REGISTER_MULTI(key) \
    REGISTER_STABLE_EXPRESSION(key, parse)

REGISTER_DOCUMENT_SOURCE(match, LiteParsed::parse, DocumentSourceMatch::createFromBson);
REGISTER_STABLE_EXPRESSION(dayOfMonth, ExpressionDayOfMonth::parse);
REGISTER_ACCUMULATOR(sum, genericParseSingleExpressionAccumulator<AccumulatorSum>);
REGISTER_STABLE_WINDOW_FUNCTION(derivative, WindowFunctionDerivative::parse);
REGISTER_TEST_DOCUMENT_SOURCE(testOnlyStage, parse);
// REGISTER_DOCUMENT_SOURCE(commentedOut, parse);

constexpr auto kHelloString = "hello"_sd;
constexpr auto kCamelCaseIsMasterString = "isMaster"_sd;
constexpr auto kLowerCaseIsMasterString = "ismaster"_sd;

class CmdHello : public BasicCommandWithReplyBuilderInterface {
public:
    CmdHello() : CmdHello(kHelloString, {}) {}
    CmdHello(const StringData cmdName, const std::initializer_list<StringData>& alias)
        : BasicCommandWithReplyBuilderInterface(cmdName, alias) {}
};
class CmdIsMaster : public CmdHello {
public:
    CmdIsMaster() : CmdHello(kCamelCaseIsMasterString, {kLowerCaseIsMasterString}) {}
};
class CleanupOrphanedCommand : public ErrmsgCommandDeprecated {
public:
    CleanupOrphanedCommand() : ErrmsgCommandDeprecated("cleanupOrphaned") {}
};
class BalancerStatusCmd : public BalancerControlCommand {
public:
    BalancerStatusCmd()
        : BalancerControlCommand("balancerStatus",
                                 "_configsvrBalancerStatus", ActionType::find, false) {}
};
class FindAndModifyCmd : public BasicCommand {
public:
    FindAndModifyCmd() : BasicCommand("findAndModify", "findandmodify") {}
};
void notACommand() {
    auto r = client.runCommand("notRegistered");
    foo(a, makeThing("alsoNotRegistered"));
}
