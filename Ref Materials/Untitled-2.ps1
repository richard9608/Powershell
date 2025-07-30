# PowerShell Parameter Attributes Cheat Sheet
# This cheat sheet provides a quick reference for common PowerShell parameter attributes used in function definitions.




| Property                          | Type                | Usage Example                                        | Effect                                             |
| --------------------------------- | ------------------- | ---------------------------------------------------- | -------------------------------------------------- |
| `Mandatory`                       | Boolean             | `[Parameter(Mandatory=$true)]`                       | Requires user to specify parameter                 |
| `Position`                        | Integer             | `[Parameter(Position=0)]`                            | Assigns position for unnamed parameters            |
| `ValueFromPipeline`               | Boolean             | `[Parameter(ValueFromPipeline=$true)]`               | Accepts input directly from pipeline objects       |
| `ValueFromPipelineByPropertyName` | Boolean             | `[Parameter(ValueFromPipelineByPropertyName=$true)]` | Binds pipeline input by matching property name     |
| `HelpMessage`                     | String              | `[Parameter(HelpMessage="Enter name")]`              | Displays message when prompting                    |
| `Alias`                           | String or String\[] | `[Alias("n","username")]`                            | Adds alternate names for the parameter             |
| `DontShow`                        | Boolean             | `[Parameter(DontShow=$true)]`                        | Hides parameter from discovery and help            |
| `ParameterSetName`                | String              | `[Parameter(ParameterSetName="Set1")]`               | Groups parameters into sets for mutual exclusivity |
