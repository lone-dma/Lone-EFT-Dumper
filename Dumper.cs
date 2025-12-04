using LoneEftDumper.SDK;
using System;
using System.Collections.Generic;
using System.Text;

namespace LoneEftDumper
{
    internal static class Dumper
    {
        public static void Dump()
        {
            const string outputPath = "dump.txt";
            Console.WriteLine("Dumping...");
            var sb = new StringBuilder();
            sb.AppendLine("Dumped via Lone-EFT-Dumper by Lone DMA.");
            sb.AppendLine("https://github.com/lone-dma/Lone-EFT-Dumper");
            sb.AppendLine();

            var klasses = IL2CPP.Class.GetTypeTable();
            Console.WriteLine($"Found {klasses.Count} classes. Processing...");

            int processedCount = 0;
            int skippedEmptyName = 0;
            int skippedExceptions = 0;

            foreach (var klass in klasses)
            {
                try
                {
                    // Check if class pointer is valid
                    if (klass.name == 0)
                    {
                        skippedEmptyName++;
                        continue;
                    }

                    // Get class name
                    string className = klass.GetName();
                    if (string.IsNullOrEmpty(className))
                    {
                        skippedEmptyName++;
                        continue;
                    }

                    // Get namespace (can be empty)
                    string namespaceName = string.Empty;
                    if (klass.namespaze != 0)
                    {
                        try
                        {
                            namespaceName = klass.GetNamespace();
                        }
                        catch
                        {
                            // Namespace read failed, continue without it
                        }
                    }
                    
                    // Get parent type name
                    string parentTypeName = "object";
                    try
                    {
                        var typeName = klass.type.GetName();
                        if (!string.IsNullOrEmpty(typeName))
                            parentTypeName = typeName;
                    }
                    catch
                    {
                        // Keep default "object"
                    }

                    // Determine class type (Class, Struct, Interface, etc.)
                    bool isInterface = (klass.flags & (uint)IL2CPP.TypeAttributes.TYPE_ATTRIBUTE_INTERFACE) != 0;
                    bool isValueType = klass.type.ValueType;
                    string classType = isInterface ? "Interface" : (isValueType ? "Struct" : "Class");

                    // Build class header
                    if (!string.IsNullOrEmpty(namespaceName))
                        sb.AppendLine($"[{classType}] {namespaceName}.{className} : {parentTypeName}");
                    else
                        sb.AppendLine($"[{classType}] {className} : {parentTypeName}");

                    // Get and dump fields
                    if (klass.field_count > 0 && klass.fields != 0)
                    {
                        try
                        {
                            var fields = klass.GetFields();
                            foreach (var field in fields)
                            {
                                try
                                {
                                    if (field.name == 0)
                                        continue;

                                    string fieldName = field.GetName();
                                    if (string.IsNullOrEmpty(fieldName))
                                        continue;

                                    string fieldTypeName = "unknown";
                                    try
                                    {
                                        if (field.type != 0)
                                        {
                                            var fieldType = field.GetTypeInfo();
                                            var typeName = fieldType.GetName();
                                            if (!string.IsNullOrEmpty(typeName))
                                                fieldTypeName = typeName;
                                        }
                                    }
                                    catch
                                    {
                                        // Keep "unknown"
                                    }

                                    // Format offset as hex with leading zeros
                                    string offsetHex = $"{field.offset:X2}";
                                    
                                    // Append field line with proper indentation
                                    sb.AppendLine($"    [{offsetHex}] {fieldName} : {fieldTypeName}");
                                }
                                catch
                                {
                                    // Skip fields that can't be read
                                    continue;
                                }
                            }
                        }
                        catch
                        {
                            // Failed to get fields, continue with next class
                        }
                    }

                    processedCount++;
                    if (processedCount % 500 == 0)
                        Console.WriteLine($"Processed {processedCount}/{klasses.Count} classes...");
                }
                catch (Exception ex)
                {
                    skippedExceptions++;
                    if (skippedExceptions <= 5)
                        Console.WriteLine($"Exception processing class: {ex.Message}");
                    continue;
                }
            }

            File.WriteAllText(outputPath, sb.ToString());
            Console.WriteLine($"\nDump complete!");
            Console.WriteLine($"  - Processed: {processedCount} classes");
            Console.WriteLine($"  - Skipped (empty name): {skippedEmptyName}");
            Console.WriteLine($"  - Skipped (exceptions): {skippedExceptions}");
            Console.WriteLine($"  - Total: {klasses.Count}");
            Console.WriteLine($"  - Output: {outputPath}");
        }
    }
}
