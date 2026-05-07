FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/SecureOpsLab.Api/SecureOpsLab.Api.csproj", "src/SecureOpsLab.Api/"]
COPY ["src/SecureOpsLab.Application/SecureOpsLab.Application.csproj", "src/SecureOpsLab.Application/"]
COPY ["src/SecureOpsLab.Contracts/SecureOpsLab.Contracts.csproj", "src/SecureOpsLab.Contracts/"]
COPY ["src/SecureOpsLab.Domain/SecureOpsLab.Domain.csproj", "src/SecureOpsLab.Domain/"]
COPY ["src/SecureOpsLab.Infrastructure/SecureOpsLab.Infrastructure.csproj", "src/SecureOpsLab.Infrastructure/"]
RUN dotnet restore "src/SecureOpsLab.Api/SecureOpsLab.Api.csproj"
COPY . .
RUN dotnet build "src/SecureOpsLab.Api/SecureOpsLab.Api.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "src/SecureOpsLab.Api/SecureOpsLab.Api.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SecureOpsLab.Api.dll"]
