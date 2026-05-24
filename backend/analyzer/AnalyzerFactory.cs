public static class AnalyzerFactory
{
    public static IAnalyzer Create(Enum code)
    {
        var className =
            $"{code}Analyzer";

        var fullName =
            $"Analyzer.{className}";

        var type =
            Type.GetType(fullName);

        if (type == null)
        {
            throw new Exception(
                $"Check class not found: {fullName}");
        }

        return (IAnalyzer)
            Activator.CreateInstance(type);
    }
}